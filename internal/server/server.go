// Package server exposes the relay's HTTP API.
package server

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	kit "go.getarcane.app/kit/pkg"

	"github.com/getarcaneapp/apns-relay/internal/apns"
	"github.com/getarcaneapp/apns-relay/internal/config"
	"github.com/getarcaneapp/apns-relay/internal/envelope"
	"github.com/getarcaneapp/apns-relay/internal/metrics"
	"github.com/getarcaneapp/apns-relay/internal/ratelimit"
	"github.com/getarcaneapp/apns-relay/internal/secrets"
	"github.com/getarcaneapp/apns-relay/internal/signing"
	"github.com/getarcaneapp/apns-relay/internal/store"
)

// PlatformAPNS is the only platform accepted today; the schema also reserves "fcm".
const PlatformAPNS = "apns"

const (
	maxAppVersionLen  = 64
	maxSubjectLen     = 128
	controlRequestAge = 5 * time.Minute
)

var deviceTokenPattern = regexp.MustCompile(`^[0-9a-fA-F]{32,400}$`)

// Options wires the server's collaborators.
type Options struct {
	Config  *config.Config
	Store   *store.Store
	Sealer  *secrets.Sealer
	Metrics *metrics.Registry
	Logger  *slog.Logger
	// Wake is called after deliveries are enqueued so the worker can pick them up promptly.
	Wake func()
	Now  func() time.Time
}

// Server is the HTTP API.
type Server struct {
	cfg     *config.Config
	store   *store.Store
	sealer  *secrets.Sealer
	metrics *metrics.Registry
	log     *slog.Logger
	wake    func()
	now     func() time.Time

	ipLimit      *ratelimit.Limiter
	channelLimit *ratelimit.Limiter
	installLimit *ratelimit.Limiter
}

// New constructs a Server.
func New(o Options) *Server {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Wake == nil {
		o.Wake = func() {}
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return &Server{
		cfg:          o.Config,
		store:        o.Store,
		sealer:       o.Sealer,
		metrics:      o.Metrics,
		log:          o.Logger,
		wake:         o.Wake,
		now:          o.Now,
		ipLimit:      ratelimit.New(o.Config.RateLimits.IPPerMinute, time.Minute),
		channelLimit: ratelimit.New(o.Config.RateLimits.ChannelPerMinute, time.Minute),
		installLimit: ratelimit.New(o.Config.RateLimits.InstallationPerMinute, time.Minute),
	}
}

// SweepLimiters drops idle rate-limit buckets.
func (s *Server) SweepLimiters() {
	s.ipLimit.Sweep()
	s.channelLimit.Sweep()
	s.installLimit.Sweep()
}

// Handler returns the routed HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /metrics", s.handleMetrics)

	mux.HandleFunc("POST /v1/channels", s.handleCreateChannel)
	mux.HandleFunc("DELETE /v1/channels/{id}", s.handleRevokeChannel)
	mux.HandleFunc("POST /v1/installations", s.handleCreateInstallation)
	mux.HandleFunc("PUT /v1/installations/{id}/token", s.handleUpdateToken)
	mux.HandleFunc("DELETE /v1/installations/{id}", s.handleDeleteInstallation)
	mux.HandleFunc("POST /v1/pair", s.handlePair)
	mux.HandleFunc("POST /v1/unpair", s.handleUnpair)
	mux.HandleFunc("POST /v1/events", s.handleEvents)
	mux.HandleFunc("POST /v1/test", s.handleTest)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := s.now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)
		w.Header().Set("Cache-Control", "no-store")
		defer func() {
			if p := recover(); p != nil {
				s.log.ErrorContext(r.Context(), "panic in handler", "panic", p, "path", r.URL.Path)
				writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
			}
			// Never log bodies, tokens or query strings; paths carry only opaque ids.
			s.log.DebugContext(r.Context(), "request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.status,
				"duration", s.now().Sub(start))
		}()
		mux.ServeHTTP(rec, r)
	})
}

// ---- middleware -----------------------------------------------------------

type statusRecorder struct {
	http.ResponseWriter

	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// ---- helpers --------------------------------------------------------------

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]apiError{"error": {Code: code, Message: message}})
}

func readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			writeError(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body exceeds limit")
		} else {
			writeError(w, http.StatusBadRequest, "bad_request", "could not read body")
		}
		return nil, false
	}
	return body, true
}

func decodeStrict(body []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.TrustProxyHeaders {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first, _, _ := strings.Cut(xff, ",")
			return strings.TrimSpace(first)
		}
		if rip := r.Header.Get("X-Real-IP"); rip != "" {
			return strings.TrimSpace(rip)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) allow(w http.ResponseWriter, limiter *ratelimit.Limiter, key string) bool {
	if limiter.Allow(key) {
		return true
	}
	s.metrics.RateLimitHits.Add(1)
	writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
	return false
}

// authInstallation validates "Authorization: Bearer <installationId>.<secret>".
func (s *Server) authInstallation(w http.ResponseWriter, r *http.Request) (*store.Installation, bool) {
	if !s.allow(w, s.ipLimit, s.clientIP(r)) {
		return nil, false
	}
	cred, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing installation credential")
		return nil, false
	}
	id, secret, ok := strings.Cut(strings.TrimSpace(cred), ".")
	if !ok || !envelope.IDPattern.MatchString(id) || secret == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized", "malformed installation credential")
		return nil, false
	}
	if !s.allow(w, s.installLimit, id) {
		return nil, false
	}
	in, err := s.store.GetInstallation(r.Context(), id)
	if err != nil || !secrets.SecretMatches(secret, in.SecretHash) {
		writeError(w, http.StatusUnauthorized, "unauthorized", "invalid installation credential")
		return nil, false
	}
	if pathID := r.PathValue("id"); pathID != "" && pathID != in.ID {
		writeError(w, http.StatusForbidden, "forbidden", "installation does not match credential")
		return nil, false
	}
	return in, true
}

// signedRequest reads the body, extracts channelId, loads the channel and verifies the signature.
func (s *Server) signedRequest(w http.ResponseWriter, r *http.Request) ([]byte, *store.Channel, bool) {
	body, ok := readBody(w, r)
	if !ok {
		return nil, nil, false
	}
	var probe struct {
		ChannelID string `json:"channelId"`
	}
	if err := json.Unmarshal(body, &probe); err != nil || !envelope.IDPattern.MatchString(probe.ChannelID) {
		writeError(w, http.StatusBadRequest, "bad_request", "body must be a JSON object with channelId")
		return nil, nil, false
	}
	if !s.allow(w, s.channelLimit, probe.ChannelID) {
		return nil, nil, false
	}
	sig, err := signing.DecodeSignature(r.Header.Get(signing.SignatureHeader))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing or malformed "+signing.SignatureHeader)
		return nil, nil, false
	}
	ch, pub, ok := s.channelKey(w, r, probe.ChannelID)
	if !ok {
		return nil, nil, false
	}
	if pub.Verify(body, sig) != nil {
		writeError(w, http.StatusUnauthorized, "bad_signature", "signature does not verify")
		return nil, nil, false
	}
	return body, ch, true
}

// channelKey loads an active channel and its verification key, writing the error response on failure.
func (s *Server) channelKey(w http.ResponseWriter, r *http.Request, id string) (*store.Channel, *signing.PublicKey, bool) {
	ch, err := s.store.GetChannel(r.Context(), id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "unknown_channel", "channel not found")
		return nil, nil, false
	case err != nil:
		s.internal(w, r, "load channel", err)
		return nil, nil, false
	case ch.RevokedAt != nil:
		writeError(w, http.StatusGone, "channel_revoked", "channel has been revoked")
		return nil, nil, false
	}
	pub, err := signing.NewPublicKey(signing.Algorithm(ch.Algorithm), ch.PublicKey)
	if err != nil {
		s.internal(w, r, "decode channel key", err)
		return nil, nil, false
	}
	return ch, pub, true
}

func (s *Server) internal(w http.ResponseWriter, r *http.Request, what string, err error) {
	s.log.ErrorContext(r.Context(), "internal error", "op", what, "error", err)
	writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
}

func (s *Server) checkFreshness(w http.ResponseWriter, issuedAt time.Time) bool {
	if issuedAt.IsZero() {
		writeError(w, http.StatusBadRequest, "bad_request", "issuedAt is required")
		return false
	}
	age := s.now().Sub(issuedAt)
	if age > controlRequestAge || age < -controlRequestAge {
		writeError(w, http.StatusBadRequest, "stale_request", "issuedAt is outside the accepted window")
		return false
	}
	return true
}

// ---- health & metrics -----------------------------------------------------

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "degraded", "database": err.Error()})
		return
	}
	pending, _ := s.store.CountPending(ctx)
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "version": config.Version, "pendingDeliveries": pending})
}

func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = s.metrics.WriteTo(w)
}

// ---- channels -------------------------------------------------------------

type createChannelRequest struct {
	Algorithm string `json:"algorithm,omitempty"`
	PublicKey string `json:"publicKey"`
}

func (s *Server) handleCreateChannel(w http.ResponseWriter, r *http.Request) {
	if !s.allow(w, s.ipLimit, s.clientIP(r)) {
		return
	}
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	var req createChannelRequest
	if err := decodeStrict(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON: "+err.Error())
		return
	}
	alg, err := signing.ParseAlgorithm(req.Algorithm)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	pub, err := signing.DecodePublicKey(alg, req.PublicKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	ch, created, err := s.store.CreateChannel(r.Context(), secrets.NewID("ch_"), string(alg), pub.Bytes())
	if err != nil {
		s.internal(w, r, "create channel", err)
		return
	}
	writeJSON(w, kit.Ternary(created, http.StatusCreated, http.StatusOK), map[string]any{"channelId": ch.ID, "algorithm": ch.Algorithm, "createdAt": ch.CreatedAt.UTC()})
}

type revokeChannelRequest struct {
	ChannelID string    `json:"channelId"`
	IssuedAt  time.Time `json:"issuedAt"`
	Nonce     string    `json:"nonce"`
}

func (s *Server) handleRevokeChannel(w http.ResponseWriter, r *http.Request) {
	body, ch, ok := s.signedRequest(w, r)
	if !ok {
		return
	}
	var req revokeChannelRequest
	if err := decodeStrict(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON: "+err.Error())
		return
	}
	if req.ChannelID != r.PathValue("id") {
		writeError(w, http.StatusBadRequest, "bad_request", "channelId does not match path")
		return
	}
	if !s.checkFreshness(w, req.IssuedAt) {
		return
	}
	if err := s.store.RevokeChannel(r.Context(), ch.ID); err != nil {
		s.internal(w, r, "revoke channel", err)
		return
	}
	s.log.InfoContext(r.Context(), "channel revoked", "channelId", ch.ID)
	w.WriteHeader(http.StatusNoContent)
}

// ---- installations --------------------------------------------------------

type createInstallationRequest struct {
	Platform        string `json:"platform"`
	APNSEnvironment string `json:"apnsEnvironment"`
	DeviceToken     string `json:"deviceToken"`
	AppVersion      string `json:"appVersion"`
}

func validateInstallationFields(platform, env, token, appVersion string) error {
	if platform != "" && platform != PlatformAPNS {
		return fmt.Errorf("platform %q is not supported", platform)
	}
	if env != "" && !apns.ValidEnvironment(env) {
		return errors.New("apnsEnvironment must be sandbox or production")
	}
	if !deviceTokenPattern.MatchString(token) {
		return errors.New("deviceToken must be a hex string")
	}
	if len(appVersion) > maxAppVersionLen {
		return errors.New("appVersion is too long")
	}
	return nil
}

func (s *Server) handleCreateInstallation(w http.ResponseWriter, r *http.Request) {
	if !s.allow(w, s.ipLimit, s.clientIP(r)) {
		return
	}
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	var req createInstallationRequest
	if err := decodeStrict(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON: "+err.Error())
		return
	}
	req.Platform = cmp.Or(req.Platform, PlatformAPNS)
	if req.APNSEnvironment == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "apnsEnvironment is required")
		return
	}
	if err := validateInstallationFields(req.Platform, req.APNSEnvironment, req.DeviceToken, req.AppVersion); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	id := secrets.NewID("ins_")
	secret := secrets.NewSecret()
	tokenEnc, err := s.sealer.Seal([]byte(strings.ToLower(req.DeviceToken)), []byte(id))
	if err != nil {
		s.internal(w, r, "seal token", err)
		return
	}
	in := &store.Installation{
		ID:              id,
		SecretHash:      secrets.HashSecret(secret),
		Platform:        req.Platform,
		APNSEnvironment: req.APNSEnvironment,
		DeviceTokenEnc:  tokenEnc,
		AppVersion:      req.AppVersion,
	}
	if err = s.store.CreateInstallation(r.Context(), in); err != nil {
		s.internal(w, r, "create installation", err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"installationId": id, "installationSecret": secret})
}

type updateTokenRequest struct {
	DeviceToken     string `json:"deviceToken"`
	APNSEnvironment string `json:"apnsEnvironment,omitempty"`
	AppVersion      string `json:"appVersion,omitempty"`
}

func (s *Server) handleUpdateToken(w http.ResponseWriter, r *http.Request) {
	in, ok := s.authInstallation(w, r)
	if !ok {
		return
	}
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	var req updateTokenRequest
	if err := decodeStrict(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON: "+err.Error())
		return
	}
	if err := validateInstallationFields("", req.APNSEnvironment, req.DeviceToken, req.AppVersion); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	tokenEnc, err := s.sealer.Seal([]byte(strings.ToLower(req.DeviceToken)), []byte(in.ID))
	if err != nil {
		s.internal(w, r, "seal token", err)
		return
	}
	if err = s.store.UpdateInstallationToken(r.Context(), in.ID, tokenEnc, req.APNSEnvironment, req.AppVersion); err != nil {
		s.internal(w, r, "update token", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeleteInstallation(w http.ResponseWriter, r *http.Request) {
	in, ok := s.authInstallation(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteInstallation(r.Context(), in.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.internal(w, r, "delete installation", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- pairing --------------------------------------------------------------

type pairRequest struct {
	PairingToken string `json:"pairingToken"`
}

func (s *Server) handlePair(w http.ResponseWriter, r *http.Request) {
	in, ok := s.authInstallation(w, r)
	if !ok {
		return
	}
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	var req pairRequest
	if err := decodeStrict(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON: "+err.Error())
		return
	}
	claims, payload, sig, err := signing.SplitPairingToken(req.PairingToken)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_pairing_token", err.Error())
		return
	}
	if !envelope.IDPattern.MatchString(claims.ChannelID) || len(claims.Subject) > maxSubjectLen || len(claims.Nonce) > 128 {
		writeError(w, http.StatusBadRequest, "bad_pairing_token", "invalid claim values")
		return
	}
	ch, pub, ok := s.channelKey(w, r, claims.ChannelID)
	if !ok {
		return
	}
	if err = signing.VerifyPairingToken(pub, claims, payload, sig, s.now()); err != nil {
		writeError(w, http.StatusUnauthorized, "bad_pairing_token", err.Error())
		return
	}
	b, err := s.store.Pair(r.Context(), secrets.NewID("rcp_"), in.ID, ch.ID, claims.Subject, claims.Nonce, time.Unix(claims.ExpiresAt, 0))
	if err != nil {
		switch {
		case errors.Is(err, store.ErrConflict):
			writeError(w, http.StatusConflict, "pairing_token_used", "pairing token has already been used")
		case errors.Is(err, store.ErrRevoked):
			writeError(w, http.StatusGone, "channel_revoked", "channel has been revoked")
		case errors.Is(err, store.ErrNotFound):
			writeError(w, http.StatusNotFound, "unknown_channel", "channel not found")
		default:
			s.internal(w, r, "pair", err)
		}
		return
	}
	_ = s.store.TouchInstallation(r.Context(), in.ID)
	writeJSON(w, http.StatusOK, map[string]any{"recipientId": b.RecipientID, "channelId": b.ChannelID})
}

type unpairRequest struct {
	RecipientID string `json:"recipientId"`
}

func (s *Server) handleUnpair(w http.ResponseWriter, r *http.Request) {
	in, ok := s.authInstallation(w, r)
	if !ok {
		return
	}
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	var req unpairRequest
	if err := decodeStrict(body, &req); err != nil || !envelope.IDPattern.MatchString(req.RecipientID) {
		writeError(w, http.StatusBadRequest, "bad_request", "recipientId is required")
		return
	}
	if err := s.store.Unpair(r.Context(), req.RecipientID, in.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.internal(w, r, "unpair", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- events ---------------------------------------------------------------

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	body, ch, ok := s.signedRequest(w, r)
	if !ok {
		s.metrics.EventsRejected.Add(1)
		return
	}
	env, err := envelope.Parse(body, s.now(), s.cfg.MaxEnvelopeAge)
	if err != nil {
		s.metrics.EventsRejected.Add(1)
		writeError(w, http.StatusBadRequest, "invalid_envelope", err.Error())
		return
	}
	s.enqueue(w, r, ch, env)
}

func (s *Server) enqueue(w http.ResponseWriter, r *http.Request, ch *store.Channel, env *envelope.Envelope) {
	payload, err := envelope.BuildAPNSPayload(env)
	if err != nil {
		s.metrics.EventsRejected.Add(1)
		writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large", err.Error())
		return
	}
	recipients, err := s.store.ResolveRecipients(r.Context(), ch.ID, env.RecipientIDs)
	if err != nil {
		s.internal(w, r, "resolve recipients", err)
		return
	}
	known := make(map[string]bool, len(recipients))
	deliveries := make([]store.NewDelivery, 0, len(recipients))
	for _, rc := range recipients {
		known[rc.RecipientID] = true
		deliveries = append(deliveries, store.NewDelivery{RecipientID: rc.RecipientID, InstallationID: rc.InstallationID, Payload: payload})
	}
	unknown := make([]string, 0)
	for _, id := range env.RecipientIDs {
		if !known[id] {
			unknown = append(unknown, id)
		}
	}
	if err = s.store.EnqueueEvent(r.Context(), ch.ID, env.EventID, envelope.DedupeKey(env), deliveries); err != nil {
		if errors.Is(err, store.ErrConflict) {
			s.metrics.EventsDuplicate.Add(1)
			writeJSON(w, http.StatusOK, map[string]any{"eventId": env.EventID, "duplicate": true, "queued": 0, "unknownRecipientIds": []string{}})
			return
		}
		s.internal(w, r, "enqueue event", err)
		return
	}
	s.metrics.EventsAccepted.Add(1)
	s.metrics.DeliveriesQueued.Add(int64(len(deliveries)))
	s.log.InfoContext(r.Context(), "event accepted",
		"channelId", ch.ID,
		"eventId", env.EventID,
		"type", env.Type,
		"queued", len(deliveries),
		"unknownRecipients", len(unknown))
	if len(deliveries) > 0 {
		s.wake()
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"eventId": env.EventID, "duplicate": false, "queued": len(deliveries), "unknownRecipientIds": unknown})
}

// ---- test -----------------------------------------------------------------

type testRequest struct {
	ChannelID   string    `json:"channelId"`
	IssuedAt    time.Time `json:"issuedAt"`
	Nonce       string    `json:"nonce"`
	RecipientID string    `json:"recipientId"`
	Title       string    `json:"title,omitempty"`
	Body        string    `json:"body,omitempty"`
}

func (s *Server) handleTest(w http.ResponseWriter, r *http.Request) {
	body, ch, ok := s.signedRequest(w, r)
	if !ok {
		return
	}
	var req testRequest
	if err := decodeStrict(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON: "+err.Error())
		return
	}
	if !s.checkFreshness(w, req.IssuedAt) {
		return
	}
	if !envelope.IDPattern.MatchString(req.Nonce) || len(req.Nonce) > 40 {
		writeError(w, http.StatusBadRequest, "bad_request", "nonce must be 1-40 url-safe characters")
		return
	}
	req.Title = cmp.Or(req.Title, "Arcane test notification")
	req.Body = cmp.Or(req.Body, "Push notifications are working for this device.")
	env := &envelope.Envelope{
		Version:      envelope.Version,
		EventID:      "test-" + req.Nonce,
		OccurredAt:   req.IssuedAt,
		Type:         "test",
		Severity:     "info",
		Title:        req.Title,
		Body:         req.Body,
		Route:        envelope.Route{Kind: envelope.RouteTab, Tab: "settings"},
		ChannelID:    ch.ID,
		RecipientIDs: []string{req.RecipientID},
	}
	if err := env.Validate(s.now(), s.cfg.MaxEnvelopeAge); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_envelope", err.Error())
		return
	}
	s.enqueue(w, r, ch, env)
}
