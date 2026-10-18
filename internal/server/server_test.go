package server_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/getarcaneapp/apns-relay/internal/apns"
	"github.com/getarcaneapp/apns-relay/internal/config"
	"github.com/getarcaneapp/apns-relay/internal/envelope"
	"github.com/getarcaneapp/apns-relay/internal/metrics"
	"github.com/getarcaneapp/apns-relay/internal/push"
	"github.com/getarcaneapp/apns-relay/internal/secrets"
	"github.com/getarcaneapp/apns-relay/internal/server"
	"github.com/getarcaneapp/apns-relay/internal/signing"
	"github.com/getarcaneapp/apns-relay/internal/store"
	"github.com/getarcaneapp/apns-relay/internal/worker"
)

// fakeSender records sends and answers with a configurable status/reason.
type fakeSender struct {
	status atomic.Int32
	reason atomic.Value
	sent   atomic.Int32
	last   atomic.Value // push.Notification
}

func newFakeSender() *fakeSender {
	f := &fakeSender{}
	f.status.Store(200)
	f.reason.Store("")
	return f
}

func (f *fakeSender) Send(_ context.Context, n push.Notification) (push.Result, error) {
	f.sent.Add(1)
	f.last.Store(n)
	status := int(f.status.Load())
	reason, _ := f.reason.Load().(string)
	switch {
	case status == 200:
		return push.Result{Outcome: push.OutcomeSent, StatusCode: 200, ID: "x"}, nil
	case status == 410 || reason == "BadDeviceToken" || reason == "UNREGISTERED":
		return push.Result{Outcome: push.OutcomeInvalidToken, StatusCode: status, Reason: reason}, nil
	case status >= 500 || status == 429:
		return push.Result{Outcome: push.OutcomeRetry, StatusCode: status, Reason: reason}, nil
	default:
		return push.Result{Outcome: push.OutcomeFailed, StatusCode: status, Reason: reason}, nil
	}
}

type harness struct {
	t      *testing.T
	srv    *httptest.Server
	store  *store.Store
	worker *worker.Worker
	apns   *fakeSender
	fcm    *fakeSender
	woken  atomic.Int32
	now    time.Time
}

type harnessSettings struct {
	cfg    *config.Config
	dbPath string
}

type harnessOption func(*harnessSettings)

func withFCM(s *harnessSettings) { s.cfg.FCM.Mode = config.FCMModeLog }

// withDB opens an existing database, e.g. to restart the relay with different config.
func withDB(path string) harnessOption {
	return func(s *harnessSettings) { s.dbPath = path }
}

func newHarness(t *testing.T, opts ...harnessOption) *harness {
	t.Helper()
	settings := &harnessSettings{
		cfg: &config.Config{
			MaxEnvelopeAge: 5 * time.Minute,
			MaxBodyBytes:   64 * 1024,
			RateLimits:     config.RateLimits{IPPerMinute: 1000, ChannelPerMinute: 1000, InstallationPerMinute: 1000},
			FCM:            config.FCM{Mode: config.FCMModeDisabled},
		},
		dbPath: t.TempDir() + "/relay.db",
	}
	for _, opt := range opts {
		opt(settings)
	}
	cfg := settings.cfg
	st, err := store.Open(settings.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	sealer, _ := secrets.NewSealer(bytes.Repeat([]byte{1}, 32))
	reg := metrics.New()
	h := &harness{t: t, store: st, apns: newFakeSender(), fcm: newFakeSender(), now: time.Now()}
	// Like cmd/main.go, the worker only gets an FCM sender when FCM is enabled.
	senders := map[string]push.Sender{push.PlatformAPNS: h.apns}
	if cfg.FCM.Enabled() {
		senders[push.PlatformFCM] = h.fcm
	}
	h.worker = worker.New(worker.Options{Store: st, Senders: senders, Sealer: sealer, Metrics: reg, Logger: slog.New(slog.DiscardHandler), MaxAttempts: 3})
	s := server.New(server.Options{
		Config: cfg, Store: st, Sealer: sealer, Metrics: reg,
		Logger: slog.New(slog.DiscardHandler),
		Wake:   func() { h.woken.Add(1) },
		Now:    func() time.Time { return h.now },
	})
	h.srv = httptest.NewServer(s.Handler())
	t.Cleanup(h.srv.Close)
	return h
}

type resp struct {
	code int
	body map[string]any
}

func (h *harness) do(method, path string, body any, headers map[string]string) resp {
	h.t.Helper()
	var raw []byte
	switch b := body.(type) {
	case nil:
	case []byte:
		raw = b
	default:
		raw, _ = json.Marshal(b)
	}
	req, _ := http.NewRequestWithContext(h.t.Context(), method, h.srv.URL+path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	out := resp{code: res.StatusCode}
	b, _ := io.ReadAll(res.Body)
	if len(b) > 0 {
		_ = json.Unmarshal(b, &out.body)
	}
	return out
}

type manager struct {
	alg       signing.Algorithm
	signer    signing.Signer
	pubB64    string
	channelID string
}

func newManager(t *testing.T, alg signing.Algorithm) *manager {
	t.Helper()
	switch alg {
	case signing.AlgEd25519:
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		return &manager{alg: alg, signer: signing.Ed25519Signer{Key: priv}, pubB64: base64.StdEncoding.EncodeToString(pub)}
	case signing.AlgMLDSA87:
		priv, err := mldsa.GenerateKey(mldsa.MLDSA87())
		if err != nil {
			t.Fatal(err)
		}
		return &manager{alg: alg, signer: signing.MLDSASigner{Key: priv}, pubB64: base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())}
	}
	t.Fatalf("unknown alg %s", alg)
	return nil
}

func (m *manager) signed(t *testing.T, body any) ([]byte, map[string]string) {
	t.Helper()
	raw, _ := json.Marshal(body)
	sig, err := m.signer.Sign(raw)
	if err != nil {
		t.Fatal(err)
	}
	return raw, map[string]string{signing.SignatureHeader: base64.StdEncoding.EncodeToString(sig)}
}

func (h *harness) register(m *manager) {
	h.t.Helper()
	r := h.do("POST", "/v1/channels", map[string]string{"algorithm": string(m.alg), "publicKey": m.pubB64}, nil)
	if r.code != http.StatusCreated {
		h.t.Fatalf("register channel: %d %v", r.code, r.body)
	}
	m.channelID = r.body["channelId"].(string)
}

type device struct {
	id, secret, recipient string
}

func (d device) auth() map[string]string {
	return map[string]string{"Authorization": "Bearer " + d.id + "." + d.secret}
}

func (h *harness) enroll(platform, token string) device {
	h.t.Helper()
	body := map[string]string{"platform": platform, "deviceToken": token, "appVersion": "1.0.0"}
	if platform == push.PlatformAPNS {
		body["apnsEnvironment"] = "sandbox"
	}
	r := h.do("POST", "/v1/installations", body, nil)
	if r.code != http.StatusCreated {
		h.t.Fatalf("enroll: %d %v", r.code, r.body)
	}
	return device{id: r.body["installationId"].(string), secret: r.body["installationSecret"].(string)}
}

func (h *harness) pair(m *manager, d *device) {
	h.t.Helper()
	claims := signing.PairingClaims{ChannelID: m.channelID, Subject: "user-1", IssuedAt: h.now.Unix(), ExpiresAt: h.now.Add(5 * time.Minute).Unix(), Nonce: secrets.NewID("n_")}
	tok, err := signing.MintPairingToken(m.signer, claims)
	if err != nil {
		h.t.Fatal(err)
	}
	r := h.do("POST", "/v1/pair", map[string]string{"pairingToken": tok}, d.auth())
	if r.code != http.StatusOK {
		h.t.Fatalf("pair: %d %v", r.code, r.body)
	}
	d.recipient = r.body["recipientId"].(string)
}

func (h *harness) envelope(m *manager, eventID string, recipients ...string) map[string]any {
	return map[string]any{
		"v": 1, "eventId": eventID, "occurredAt": h.now.UTC().Format(time.RFC3339Nano),
		"type": "container_update", "severity": "warning",
		"environmentId": "env-1", "environmentName": "Prod",
		"resource": map[string]string{"kind": "container", "id": "c1", "name": "web"},
		"title":    "Container updated", "body": "web restarted",
		"route":     map[string]string{"kind": "container", "environmentId": "env-1", "id": "c1"},
		"channelId": m.channelID, "recipientIds": recipients,
	}
}

func TestFullFlow(t *testing.T) {
	for _, alg := range []signing.Algorithm{signing.AlgEd25519, signing.AlgMLDSA87} {
		t.Run(string(alg), func(t *testing.T) { testFullFlow(t, alg) })
	}
}

func testFullFlow(t *testing.T, alg signing.Algorithm) {
	h := newHarness(t)
	m := newManager(t, alg)
	h.register(m)

	// Registration is idempotent for the same key.
	again := h.do("POST", "/v1/channels", map[string]string{"algorithm": string(alg), "publicKey": m.pubB64}, nil)
	if again.code != http.StatusOK || again.body["channelId"] != m.channelID {
		t.Fatalf("re-register: %d %v", again.code, again.body)
	}

	d := h.enroll(push.PlatformAPNS, strings.Repeat("ab", 32))
	h.pair(m, &d)

	raw, hdr := m.signed(t, h.envelope(m, "evt-1", d.recipient, "rcp_missing"))
	r := h.do("POST", "/v1/events", raw, hdr)
	if r.code != http.StatusAccepted || r.body["queued"].(float64) != 1 {
		t.Fatalf("events: %d %v", r.code, r.body)
	}
	if unknown := r.body["unknownRecipientIds"].([]any); len(unknown) != 1 || unknown[0] != "rcp_missing" {
		t.Fatalf("unknown recipients: %v", r.body)
	}
	if h.woken.Load() != 1 {
		t.Fatal("worker should be woken")
	}
	// Duplicate event id is a no-op.
	r = h.do("POST", "/v1/events", raw, hdr)
	if r.code != http.StatusOK || r.body["duplicate"] != true {
		t.Fatalf("duplicate: %d %v", r.code, r.body)
	}

	if _, err := h.worker.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	if h.apns.sent.Load() != 1 {
		t.Fatalf("expected 1 send, got %d", h.apns.sent.Load())
	}
	n := h.apns.last.Load().(push.Notification)
	if n.DeviceToken != strings.Repeat("ab", 32) || n.Environment != string(apns.EnvironmentSandbox) ||
		!strings.HasPrefix(n.CollapseID, "d-") || len(n.CollapseID) > 64 {
		t.Fatalf("unexpected notification: %+v", n)
	}
	if strings.Contains(string(n.Payload), d.recipient) {
		t.Fatal("payload leaked recipient id")
	}
	ds, _ := h.store.ListDeliveriesByEvent(t.Context(), m.channelID, "evt-1")
	if len(ds) != 1 || ds[0].Status != store.DeliverySent || ds[0].Payload != nil {
		t.Fatalf("delivery state: %+v", ds)
	}

	// Test push to one recipient.
	raw, hdr = m.signed(t, map[string]any{"channelId": m.channelID, "issuedAt": h.now.UTC(), "nonce": "abc123", "recipientId": d.recipient})
	if r = h.do("POST", "/v1/test", raw, hdr); r.code != http.StatusAccepted {
		t.Fatalf("test: %d %v", r.code, r.body)
	}

	// Unpair, then events for that recipient are unknown.
	if r = h.do("POST", "/v1/unpair", map[string]string{"recipientId": d.recipient}, d.auth()); r.code != http.StatusNoContent {
		t.Fatalf("unpair: %d %v", r.code, r.body)
	}
	raw, hdr = m.signed(t, h.envelope(m, "evt-2", d.recipient))
	r = h.do("POST", "/v1/events", raw, hdr)
	if r.code != http.StatusAccepted || r.body["queued"].(float64) != 0 || h.woken.Load() != 2 {
		t.Fatalf("after unpair: %d %v woken=%d", r.code, r.body, h.woken.Load())
	}

	// Revoke channel (signed), then everything is 410.
	raw, hdr = m.signed(t, map[string]any{"channelId": m.channelID, "issuedAt": h.now.UTC(), "nonce": "r1"})
	if r = h.do("DELETE", "/v1/channels/"+m.channelID, raw, hdr); r.code != http.StatusNoContent {
		t.Fatalf("revoke: %d %v", r.code, r.body)
	}
	raw, hdr = m.signed(t, h.envelope(m, "evt-3", d.recipient))
	if r = h.do("POST", "/v1/events", raw, hdr); r.code != http.StatusGone {
		t.Fatalf("post-revoke: %d %v", r.code, r.body)
	}
}

func TestSignatureAndAuthFailures(t *testing.T) {
	h := newHarness(t)
	m := newManager(t, signing.AlgEd25519)
	h.register(m)
	d := h.enroll(push.PlatformAPNS, strings.Repeat("cd", 32))
	h.pair(m, &d)

	raw, hdr := m.signed(t, h.envelope(m, "evt-1", d.recipient))
	// Tampered body.
	tampered := bytes.Replace(raw, []byte("web restarted"), []byte("web exploded"), 1)
	if r := h.do("POST", "/v1/events", tampered, hdr); r.code != http.StatusUnauthorized {
		t.Fatalf("tampered body: %d %v", r.code, r.body)
	}
	// Missing signature.
	if r := h.do("POST", "/v1/events", raw, nil); r.code != http.StatusUnauthorized {
		t.Fatalf("missing signature: %d", r.code)
	}
	// Signed by a different manager.
	other := newManager(t, signing.AlgEd25519)
	h.register(other)
	_, otherHdr := other.signed(t, h.envelope(m, "evt-1", d.recipient))
	if r := h.do("POST", "/v1/events", raw, otherHdr); r.code != http.StatusUnauthorized {
		t.Fatalf("wrong key: %d", r.code)
	}
	// Stale envelope.
	stale := h.envelope(m, "evt-old", d.recipient)
	stale["occurredAt"] = h.now.Add(-time.Hour).UTC().Format(time.RFC3339)
	raw, hdr = m.signed(t, stale)
	if r := h.do("POST", "/v1/events", raw, hdr); r.code != http.StatusBadRequest {
		t.Fatalf("stale: %d %v", r.code, r.body)
	}
	// Envelope with extra field (e.g. a server URL) is rejected.
	leaky := h.envelope(m, "evt-leak", d.recipient)
	leaky["serverUrl"] = "https://arcane.example"
	raw, hdr = m.signed(t, leaky)
	if r := h.do("POST", "/v1/events", raw, hdr); r.code != http.StatusBadRequest {
		t.Fatalf("unknown field: %d %v", r.code, r.body)
	}
	// Other manager cannot target our recipient: it is simply unknown on its channel.
	raw, hdr = other.signed(t, h.envelope(other, "evt-x", d.recipient))
	if r := h.do("POST", "/v1/events", raw, hdr); r.code != http.StatusAccepted || r.body["queued"].(float64) != 0 {
		t.Fatalf("cross-channel: %d %v", r.code, r.body)
	}

	// Installation auth failures.
	bad := device{id: d.id, secret: "wrong"}
	if r := h.do("POST", "/v1/unpair", map[string]string{"recipientId": d.recipient}, bad.auth()); r.code != http.StatusUnauthorized {
		t.Fatalf("bad secret: %d", r.code)
	}
	other2 := h.enroll(push.PlatformAPNS, strings.Repeat("ef", 32))
	if r := h.do("DELETE", "/v1/installations/"+d.id, nil, other2.auth()); r.code != http.StatusForbidden {
		t.Fatalf("cross-installation delete: %d", r.code)
	}
	// Pairing token replay.
	tok, _ := signing.MintPairingToken(m.signer, signing.PairingClaims{ChannelID: m.channelID, Subject: "u", IssuedAt: h.now.Unix(), ExpiresAt: h.now.Add(time.Minute).Unix(), Nonce: "once"})
	if r := h.do("POST", "/v1/pair", map[string]string{"pairingToken": tok}, other2.auth()); r.code != http.StatusOK {
		t.Fatalf("pair: %d %v", r.code, r.body)
	}
	if r := h.do("POST", "/v1/pair", map[string]string{"pairingToken": tok}, d.auth()); r.code != http.StatusConflict {
		t.Fatalf("replayed pairing token: %d %v", r.code, r.body)
	}
	// Unsupported platforms: FCM is disabled in this harness.
	if r := h.do("POST", "/v1/installations", map[string]string{"platform": "fcm", "apnsEnvironment": "sandbox", "deviceToken": "abcd"}, nil); r.code != http.StatusBadRequest {
		t.Fatalf("fcm: %d", r.code)
	}
	if r := h.do("POST", "/v1/installations", map[string]string{"platform": "fcm", "deviceToken": fcmToken}, nil); r.code != http.StatusBadRequest {
		t.Fatalf("fcm while disabled: %d %v", r.code, r.body)
	}
	if r := h.do("POST", "/v1/installations", map[string]string{"platform": "webpush", "deviceToken": fcmToken}, nil); r.code != http.StatusBadRequest {
		t.Fatalf("unknown platform: %d %v", r.code, r.body)
	}
}

func TestWorkerInvalidTokenRemovesInstallation(t *testing.T) {
	h := newHarness(t)
	m := newManager(t, signing.AlgEd25519)
	h.register(m)
	d := h.enroll(push.PlatformAPNS, strings.Repeat("11", 32))
	h.pair(m, &d)
	raw, hdr := m.signed(t, h.envelope(m, "evt-1", d.recipient))
	h.do("POST", "/v1/events", raw, hdr)
	raw, hdr = m.signed(t, h.envelope(m, "evt-2", d.recipient))
	h.do("POST", "/v1/events", raw, hdr)

	h.apns.status.Store(410)
	h.apns.reason.Store("Unregistered")
	if _, err := h.worker.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.GetInstallation(t.Context(), d.id); err == nil {
		t.Fatal("installation should have been removed")
	}
	for _, ev := range []string{"evt-1", "evt-2"} {
		ds, _ := h.store.ListDeliveriesByEvent(t.Context(), m.channelID, ev)
		if len(ds) != 1 || ds[0].Status != store.DeliveryDropped {
			t.Fatalf("%s: %+v", ev, ds)
		}
	}
	if h.apns.sent.Load() != 1 {
		t.Fatalf("second delivery should have been dropped without sending, sent=%d", h.apns.sent.Load())
	}
}

func TestWorkerRetriesThenFails(t *testing.T) {
	h := newHarness(t)
	m := newManager(t, signing.AlgEd25519)
	h.register(m)
	d := h.enroll(push.PlatformAPNS, strings.Repeat("22", 32))
	h.pair(m, &d)
	raw, hdr := m.signed(t, h.envelope(m, "evt-1", d.recipient))
	h.do("POST", "/v1/events", raw, hdr)

	h.apns.status.Store(503)
	h.apns.reason.Store("ServiceUnavailable")
	if _, err := h.worker.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	ds, _ := h.store.ListDeliveriesByEvent(t.Context(), m.channelID, "evt-1")
	if ds[0].Status != store.DeliveryPending || ds[0].Attempts != 1 || !ds[0].NextAttemptAt.After(time.Now()) {
		t.Fatalf("expected retry scheduled: %+v", ds[0])
	}
	// Force the delivery due again and exhaust attempts (MaxAttempts=3).
	for i := 0; i < 2; i++ {
		if err := h.store.MarkRetry(t.Context(), ds[0].ID, time.Now().Add(-time.Second), "force"); err != nil {
			t.Fatal(err)
		}
		if _, err := h.worker.Drain(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	ds, _ = h.store.ListDeliveriesByEvent(t.Context(), m.channelID, "evt-1")
	if ds[0].Status != store.DeliveryFailed {
		t.Fatalf("expected failed after max attempts: %+v", ds[0])
	}
}

func TestTokenRotation(t *testing.T) {
	h := newHarness(t)
	m := newManager(t, signing.AlgEd25519)
	h.register(m)
	d := h.enroll(push.PlatformAPNS, strings.Repeat("33", 32))
	h.pair(m, &d)
	newTok := strings.Repeat("44", 32)
	if r := h.do("PUT", "/v1/installations/"+d.id+"/token", map[string]string{"deviceToken": newTok, "apnsEnvironment": "production", "appVersion": "1.1.0"}, d.auth()); r.code != http.StatusNoContent {
		t.Fatalf("rotate: %d %v", r.code, r.body)
	}
	raw, hdr := m.signed(t, h.envelope(m, "evt-1", d.recipient))
	h.do("POST", "/v1/events", raw, hdr)
	if _, err := h.worker.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	n := h.apns.last.Load().(push.Notification)
	if n.DeviceToken != newTok || n.Environment != string(apns.EnvironmentProduction) {
		t.Fatalf("rotated token not used: %+v", n)
	}
}

func TestHealthAndMetrics(t *testing.T) {
	h := newHarness(t)
	if r := h.do("GET", "/healthz", nil, nil); r.code != http.StatusOK || r.body["status"] != "ok" {
		t.Fatalf("health: %d %v", r.code, r.body)
	}
	b := h.metrics()
	if !strings.Contains(b, "relay_events_accepted_total") || !strings.Contains(b, "relay_apns_responses_total") ||
		!strings.Contains(b, "relay_fcm_responses_total") {
		t.Fatalf("metrics missing: %s", b)
	}
}

func (h *harness) metrics() string {
	h.t.Helper()
	req, _ := http.NewRequestWithContext(h.t.Context(), http.MethodGet, h.srv.URL+"/metrics", http.NoBody)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(res.Body)
	return string(b)
}

func TestBodyLimit(t *testing.T) {
	h := newHarness(t)
	big := bytes.Repeat([]byte("a"), 70*1024)
	if r := h.do("POST", "/v1/channels", big, nil); r.code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", r.code)
	}
}

// fcmToken looks like a real FCM registration token: mixed case, ':' '-' and '_'.
var fcmToken = "eXaMpLe-Dev1ce:APA91b" + strings.Repeat("Hq_7-Zk", 20)

func TestFCMFlow(t *testing.T) {
	h := newHarness(t, withFCM)
	m := newManager(t, signing.AlgEd25519)
	h.register(m)
	d := h.enroll(push.PlatformFCM, fcmToken)
	h.pair(m, &d)

	raw, hdr := m.signed(t, h.envelope(m, "evt-1", d.recipient))
	if r := h.do("POST", "/v1/events", raw, hdr); r.code != http.StatusAccepted || r.body["queued"].(float64) != 1 {
		t.Fatalf("events: %d %v", r.code, r.body)
	}
	if _, err := h.worker.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	if h.fcm.sent.Load() != 1 || h.apns.sent.Load() != 0 {
		t.Fatalf("sends: fcm=%d apns=%d", h.fcm.sent.Load(), h.apns.sent.Load())
	}
	n := h.fcm.last.Load().(push.Notification)
	// FCM tokens are case-sensitive and must reach Google exactly as registered.
	if n.DeviceToken != fcmToken || n.Environment != "" {
		t.Fatalf("unexpected notification: %+v", n)
	}
	var p envelope.FCMPayload
	if err := json.Unmarshal(n.Payload, &p); err != nil {
		t.Fatal(err)
	}
	if p.Data.Title != "Container updated" || p.Data.Tag != n.CollapseID || p.Data.ThreadIdentifier != "env-1:container_update" {
		t.Fatalf("unexpected payload: %s", n.Payload)
	}
	if strings.Contains(string(n.Payload), d.recipient) {
		t.Fatal("payload leaked recipient id")
	}

	// A test push goes out over FCM as well.
	raw, hdr = m.signed(t, map[string]any{"channelId": m.channelID, "issuedAt": h.now.UTC(), "nonce": "abc123", "recipientId": d.recipient})
	if r := h.do("POST", "/v1/test", raw, hdr); r.code != http.StatusAccepted {
		t.Fatalf("test: %d %v", r.code, r.body)
	}
	if _, err := h.worker.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	if h.fcm.sent.Load() != 2 {
		t.Fatalf("test push not sent over fcm: %d", h.fcm.sent.Load())
	}
}

func TestFCMRecipientsSkippedWhileDisabled(t *testing.T) {
	dbPath := t.TempDir() + "/relay.db"
	before := newHarness(t, withFCM, withDB(dbPath))
	m := newManager(t, signing.AlgEd25519)
	before.register(m)
	ios := before.enroll(push.PlatformAPNS, strings.Repeat("ab", 32))
	before.pair(m, &ios)
	android := before.enroll(push.PlatformFCM, fcmToken)
	before.pair(m, &android)

	// The relay restarts with FCM disabled; the Android installation is still paired.
	h := newHarness(t, withDB(dbPath))
	raw, hdr := m.signed(t, h.envelope(m, "evt-1", ios.recipient, android.recipient))
	r := h.do("POST", "/v1/events", raw, hdr)
	if r.code != http.StatusAccepted || r.body["queued"].(float64) != 1 || len(r.body["unknownRecipientIds"].([]any)) != 0 {
		t.Fatalf("events: %d %v", r.code, r.body)
	}
	if _, err := h.worker.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	if h.apns.sent.Load() != 1 || h.fcm.sent.Load() != 0 {
		t.Fatalf("sends: apns=%d fcm=%d", h.apns.sent.Load(), h.fcm.sent.Load())
	}
}

func TestMixedPlatformRecipients(t *testing.T) {
	h := newHarness(t, withFCM)
	m := newManager(t, signing.AlgEd25519)
	h.register(m)
	ios := h.enroll(push.PlatformAPNS, strings.Repeat("ab", 32))
	h.pair(m, &ios)
	android := h.enroll(push.PlatformFCM, fcmToken)
	h.pair(m, &android)

	raw, hdr := m.signed(t, h.envelope(m, "evt-1", ios.recipient, android.recipient))
	if r := h.do("POST", "/v1/events", raw, hdr); r.code != http.StatusAccepted || r.body["queued"].(float64) != 2 {
		t.Fatalf("events: %d %v", r.code, r.body)
	}
	if _, err := h.worker.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	if h.apns.sent.Load() != 1 || h.fcm.sent.Load() != 1 {
		t.Fatalf("sends: apns=%d fcm=%d", h.apns.sent.Load(), h.fcm.sent.Load())
	}
	// Each platform counts into its own series; the APNs line format is what dashboards parse.
	metricsText := h.metrics()
	for _, line := range []string{"\nrelay_apns_responses_total{status=\"200\",reason=\"\"} 1\n", "\nrelay_fcm_responses_total{status=\"200\",reason=\"\"} 1\n"} {
		if !strings.Contains(metricsText, line) {
			t.Fatalf("metrics missing %q:\n%s", line, metricsText)
		}
	}
	var apnsPayload envelope.APNSPayload
	if err := json.Unmarshal(h.apns.last.Load().(push.Notification).Payload, &apnsPayload); err != nil || apnsPayload.APS.Alert.Title == "" {
		t.Fatalf("apns got a non-APNs payload: %v", err)
	}
	var fcmPayload envelope.FCMPayload
	if err := json.Unmarshal(h.fcm.last.Load().(push.Notification).Payload, &fcmPayload); err != nil || fcmPayload.Data.Body == "" {
		t.Fatalf("fcm got a non-FCM payload: %v", err)
	}
	if apnsPayload.Arcane.DedupeKey != fcmPayload.Data.Tag {
		t.Fatal("both platforms should share the dedupe key")
	}
}

func TestFCMRegistrationRules(t *testing.T) {
	h := newHarness(t, withFCM)
	cases := map[string]map[string]string{
		"apnsEnvironment": {"platform": "fcm", "apnsEnvironment": "sandbox", "deviceToken": fcmToken},
		"short token":     {"platform": "fcm", "deviceToken": "abc:def"},
		"bad characters":  {"platform": "fcm", "deviceToken": fcmToken + "/=="},
	}
	for name, body := range cases {
		if r := h.do("POST", "/v1/installations", body, nil); r.code != http.StatusBadRequest {
			t.Errorf("%s: %d %v", name, r.code, r.body)
		}
	}
	// APNs still requires its environment.
	if r := h.do("POST", "/v1/installations", map[string]string{"deviceToken": strings.Repeat("ab", 32)}, nil); r.code != http.StatusBadRequest {
		t.Fatalf("apns without environment: %d", r.code)
	}

	d := h.enroll(push.PlatformFCM, fcmToken)
	if r := h.do("PUT", "/v1/installations/"+d.id+"/token", map[string]string{"deviceToken": fcmToken, "apnsEnvironment": "production"}, d.auth()); r.code != http.StatusBadRequest {
		t.Fatalf("fcm rotation with apnsEnvironment: %d %v", r.code, r.body)
	}
	if r := h.do("PUT", "/v1/installations/"+d.id+"/token", map[string]string{"deviceToken": strings.Repeat("ab", 16)}, d.auth()); r.code != http.StatusBadRequest {
		t.Fatalf("fcm rotation to a short token: %d %v", r.code, r.body)
	}
	rotated := "NeW" + fcmToken
	if r := h.do("PUT", "/v1/installations/"+d.id+"/token", map[string]string{"deviceToken": rotated, "appVersion": "1.1.0"}, d.auth()); r.code != http.StatusNoContent {
		t.Fatalf("fcm rotation: %d %v", r.code, r.body)
	}
	m := newManager(t, signing.AlgEd25519)
	h.register(m)
	h.pair(m, &d)
	raw, hdr := m.signed(t, h.envelope(m, "evt-1", d.recipient))
	h.do("POST", "/v1/events", raw, hdr)
	if _, err := h.worker.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := h.fcm.last.Load().(push.Notification); n.DeviceToken != rotated {
		t.Fatalf("rotated token not used as-is: %q", n.DeviceToken)
	}
}

func TestWorkerInvalidFCMTokenRemovesInstallation(t *testing.T) {
	h := newHarness(t, withFCM)
	m := newManager(t, signing.AlgEd25519)
	h.register(m)
	d := h.enroll(push.PlatformFCM, fcmToken)
	h.pair(m, &d)
	raw, hdr := m.signed(t, h.envelope(m, "evt-1", d.recipient))
	h.do("POST", "/v1/events", raw, hdr)

	h.fcm.status.Store(404)
	h.fcm.reason.Store("UNREGISTERED")
	if _, err := h.worker.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.GetInstallation(t.Context(), d.id); err == nil {
		t.Fatal("installation should have been removed")
	}
	ds, _ := h.store.ListDeliveriesByEvent(t.Context(), m.channelID, "evt-1")
	if len(ds) != 1 || ds[0].Status != store.DeliveryDropped {
		t.Fatalf("delivery state: %+v", ds)
	}
}
