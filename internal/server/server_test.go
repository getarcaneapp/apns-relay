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
	"github.com/getarcaneapp/apns-relay/internal/metrics"
	"github.com/getarcaneapp/apns-relay/internal/secrets"
	"github.com/getarcaneapp/apns-relay/internal/server"
	"github.com/getarcaneapp/apns-relay/internal/signing"
	"github.com/getarcaneapp/apns-relay/internal/store"
	"github.com/getarcaneapp/apns-relay/internal/worker"
)

// fakeAPNS records sends and answers with a configurable status/reason.
type fakeAPNS struct {
	status atomic.Int32
	reason atomic.Value
	sent   atomic.Int32
	last   atomic.Value // apns.Notification
}

func (f *fakeAPNS) Send(_ context.Context, n apns.Notification) (apns.Result, error) {
	f.sent.Add(1)
	f.last.Store(n)
	status := int(f.status.Load())
	reason, _ := f.reason.Load().(string)
	switch {
	case status == 200:
		return apns.Result{Outcome: apns.OutcomeSent, StatusCode: 200, APNSID: "x"}, nil
	case status == 410 || reason == "BadDeviceToken":
		return apns.Result{Outcome: apns.OutcomeInvalidToken, StatusCode: status, Reason: reason}, nil
	case status >= 500 || status == 429:
		return apns.Result{Outcome: apns.OutcomeRetry, StatusCode: status, Reason: reason}, nil
	default:
		return apns.Result{Outcome: apns.OutcomeFailed, StatusCode: status, Reason: reason}, nil
	}
}

type harness struct {
	t      *testing.T
	srv    *httptest.Server
	store  *store.Store
	worker *worker.Worker
	apns   *fakeAPNS
	woken  atomic.Int32
	now    time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	cfg := &config.Config{
		MaxEnvelopeAge: 5 * time.Minute,
		MaxBodyBytes:   64 * 1024,
		RateLimits:     config.RateLimits{IPPerMinute: 1000, ChannelPerMinute: 1000, InstallationPerMinute: 1000},
	}
	st, err := store.Open(t.TempDir() + "/relay.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	sealer, _ := secrets.NewSealer(bytes.Repeat([]byte{1}, 32))
	reg := metrics.New()
	fake := &fakeAPNS{}
	fake.status.Store(200)
	fake.reason.Store("")
	h := &harness{t: t, store: st, apns: fake, now: time.Now()}
	h.worker = worker.New(worker.Options{Store: st, Sender: fake, Sealer: sealer, Metrics: reg, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), MaxAttempts: 3})
	s := server.New(server.Options{
		Config: cfg, Store: st, Sealer: sealer, Metrics: reg,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
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
	req, _ := http.NewRequestWithContext(context.Background(), method, h.srv.URL+path, bytes.NewReader(raw))
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

func (h *harness) enroll(token string) device {
	h.t.Helper()
	r := h.do("POST", "/v1/installations", map[string]string{"platform": "apns", "apnsEnvironment": "sandbox", "deviceToken": token, "appVersion": "1.0.0"}, nil)
	if r.code != http.StatusCreated {
		h.t.Fatalf("enroll: %d %v", r.code, r.body)
	}
	return device{id: r.body["installationId"].(string), secret: r.body["installationSecret"].(string)}
}

func (h *harness) pair(m *manager, d *device) {
	h.t.Helper()
	tok, err := signing.MintPairingToken(m.signer, signing.PairingClaims{ChannelID: m.channelID, Subject: "user-1", IssuedAt: h.now.Unix(), ExpiresAt: h.now.Add(5 * time.Minute).Unix(), Nonce: secrets.NewID("n_")})
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
		t.Run(string(alg), func(t *testing.T) {
			h := newHarness(t)
			m := newManager(t, alg)
			h.register(m)

			// Registration is idempotent for the same key.
			again := h.do("POST", "/v1/channels", map[string]string{"algorithm": string(alg), "publicKey": m.pubB64}, nil)
			if again.code != http.StatusOK || again.body["channelId"] != m.channelID {
				t.Fatalf("re-register: %d %v", again.code, again.body)
			}

			d := h.enroll(strings.Repeat("ab", 32))
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

			if _, err := h.worker.Drain(context.Background()); err != nil {
				t.Fatal(err)
			}
			if h.apns.sent.Load() != 1 {
				t.Fatalf("expected 1 send, got %d", h.apns.sent.Load())
			}
			n := h.apns.last.Load().(apns.Notification)
			if n.DeviceToken != strings.Repeat("ab", 32) || n.Environment != apns.EnvironmentSandbox || n.CollapseID != "evt-1" {
				t.Fatalf("unexpected notification: %+v", n)
			}
			if strings.Contains(string(n.Payload), d.recipient) {
				t.Fatal("payload leaked recipient id")
			}
			ds, _ := h.store.ListDeliveriesByEvent(context.Background(), m.channelID, "evt-1")
			if len(ds) != 1 || ds[0].Status != store.DeliverySent || ds[0].Payload != nil {
				t.Fatalf("delivery state: %+v", ds)
			}

			// Test push to one recipient.
			raw, hdr = m.signed(t, map[string]any{"channelId": m.channelID, "issuedAt": h.now.UTC(), "nonce": "abc123", "recipientId": d.recipient})
			if r := h.do("POST", "/v1/test", raw, hdr); r.code != http.StatusAccepted {
				t.Fatalf("test: %d %v", r.code, r.body)
			}

			// Unpair, then events for that recipient are unknown.
			if r := h.do("POST", "/v1/unpair", map[string]string{"recipientId": d.recipient}, d.auth()); r.code != http.StatusNoContent {
				t.Fatalf("unpair: %d %v", r.code, r.body)
			}
			raw, hdr = m.signed(t, h.envelope(m, "evt-2", d.recipient))
			r = h.do("POST", "/v1/events", raw, hdr)
			if r.code != http.StatusAccepted || r.body["queued"].(float64) != 0 || h.woken.Load() != 2 {
				t.Fatalf("after unpair: %d %v woken=%d", r.code, r.body, h.woken.Load())
			}

			// Revoke channel (signed), then everything is 410.
			raw, hdr = m.signed(t, map[string]any{"channelId": m.channelID, "issuedAt": h.now.UTC(), "nonce": "r1"})
			if r := h.do("DELETE", "/v1/channels/"+m.channelID, raw, hdr); r.code != http.StatusNoContent {
				t.Fatalf("revoke: %d %v", r.code, r.body)
			}
			raw, hdr = m.signed(t, h.envelope(m, "evt-3", d.recipient))
			if r := h.do("POST", "/v1/events", raw, hdr); r.code != http.StatusGone {
				t.Fatalf("post-revoke: %d %v", r.code, r.body)
			}
		})
	}
}

func TestSignatureAndAuthFailures(t *testing.T) {
	h := newHarness(t)
	m := newManager(t, signing.AlgEd25519)
	h.register(m)
	d := h.enroll(strings.Repeat("cd", 32))
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
	other2 := h.enroll(strings.Repeat("ef", 32))
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
	// Unsupported platform.
	if r := h.do("POST", "/v1/installations", map[string]string{"platform": "fcm", "apnsEnvironment": "sandbox", "deviceToken": "abcd"}, nil); r.code != http.StatusBadRequest {
		t.Fatalf("fcm: %d", r.code)
	}
}

func TestWorkerInvalidTokenRemovesInstallation(t *testing.T) {
	h := newHarness(t)
	m := newManager(t, signing.AlgEd25519)
	h.register(m)
	d := h.enroll(strings.Repeat("11", 32))
	h.pair(m, &d)
	raw, hdr := m.signed(t, h.envelope(m, "evt-1", d.recipient))
	h.do("POST", "/v1/events", raw, hdr)
	raw, hdr = m.signed(t, h.envelope(m, "evt-2", d.recipient))
	h.do("POST", "/v1/events", raw, hdr)

	h.apns.status.Store(410)
	h.apns.reason.Store("Unregistered")
	if _, err := h.worker.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.GetInstallation(context.Background(), d.id); err == nil {
		t.Fatal("installation should have been removed")
	}
	for _, ev := range []string{"evt-1", "evt-2"} {
		ds, _ := h.store.ListDeliveriesByEvent(context.Background(), m.channelID, ev)
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
	d := h.enroll(strings.Repeat("22", 32))
	h.pair(m, &d)
	raw, hdr := m.signed(t, h.envelope(m, "evt-1", d.recipient))
	h.do("POST", "/v1/events", raw, hdr)

	h.apns.status.Store(503)
	h.apns.reason.Store("ServiceUnavailable")
	if _, err := h.worker.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	ds, _ := h.store.ListDeliveriesByEvent(context.Background(), m.channelID, "evt-1")
	if ds[0].Status != store.DeliveryPending || ds[0].Attempts != 1 || !ds[0].NextAttemptAt.After(time.Now()) {
		t.Fatalf("expected retry scheduled: %+v", ds[0])
	}
	// Force the delivery due again and exhaust attempts (MaxAttempts=3).
	for i := 0; i < 2; i++ {
		if err := h.store.MarkRetry(context.Background(), ds[0].ID, time.Now().Add(-time.Second), "force"); err != nil {
			t.Fatal(err)
		}
		if _, err := h.worker.Drain(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	ds, _ = h.store.ListDeliveriesByEvent(context.Background(), m.channelID, "evt-1")
	if ds[0].Status != store.DeliveryFailed {
		t.Fatalf("expected failed after max attempts: %+v", ds[0])
	}
}

func TestTokenRotation(t *testing.T) {
	h := newHarness(t)
	m := newManager(t, signing.AlgEd25519)
	h.register(m)
	d := h.enroll(strings.Repeat("33", 32))
	h.pair(m, &d)
	newTok := strings.Repeat("44", 32)
	if r := h.do("PUT", "/v1/installations/"+d.id+"/token", map[string]string{"deviceToken": newTok, "apnsEnvironment": "production", "appVersion": "1.1.0"}, d.auth()); r.code != http.StatusNoContent {
		t.Fatalf("rotate: %d %v", r.code, r.body)
	}
	raw, hdr := m.signed(t, h.envelope(m, "evt-1", d.recipient))
	h.do("POST", "/v1/events", raw, hdr)
	if _, err := h.worker.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	n := h.apns.last.Load().(apns.Notification)
	if n.DeviceToken != newTok || n.Environment != apns.EnvironmentProduction {
		t.Fatalf("rotated token not used: %+v", n)
	}
}

func TestHealthAndMetrics(t *testing.T) {
	h := newHarness(t)
	if r := h.do("GET", "/healthz", nil, nil); r.code != http.StatusOK || r.body["status"] != "ok" {
		t.Fatalf("health: %d %v", r.code, r.body)
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, h.srv.URL+"/metrics", nil)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(res.Body)
	if !strings.Contains(string(b), "relay_events_accepted_total") {
		t.Fatalf("metrics missing: %s", b)
	}
}

func TestBodyLimit(t *testing.T) {
	h := newHarness(t)
	big := bytes.Repeat([]byte("a"), 70*1024)
	if r := h.do("POST", "/v1/channels", big, nil); r.code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", r.code)
	}
}
