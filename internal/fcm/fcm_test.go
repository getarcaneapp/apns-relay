package fcm

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/getarcaneapp/apns-relay/internal/push"
)

func TestAssertionIsValidRS256(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	p := &tokenProvider{email: "relay@proj.iam.gserviceaccount.com", key: key, tokenURL: "http://127.0.0.1:9/token", audience: "https://oauth2.example/token"}
	jwt, err := p.assertion(now)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("bad jwt %q", jwt)
	}
	var header map[string]string
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	_ = json.Unmarshal(hb, &header)
	if header["alg"] != "RS256" || header["typ"] != "JWT" {
		t.Fatalf("bad header %v", header)
	}
	var claims map[string]any
	cb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	_ = json.Unmarshal(cb, &claims)
	// aud is the service account's token_uri even when tokens are fetched elsewhere,
	// and iat is backdated to tolerate a fast clock while keeping a 1h lifetime.
	iat := now.Add(-clockSkew)
	if claims["iss"] != p.email || claims["aud"] != p.audience || claims["scope"] != messagingScope ||
		int64(claims["iat"].(float64)) != iat.Unix() || int64(claims["exp"].(float64)) != iat.Add(time.Hour).Unix() {
		t.Fatalf("bad claims %v", claims)
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err = rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
}

// fakeGoogle serves both the OAuth2 token endpoint and the FCM send endpoint.
type fakeGoogle struct {
	t          *testing.T
	tokenCalls atomic.Int32
	// tokenStatus and tokenBody, when set, replace a successful token response.
	tokenStatus int
	tokenBody   string
	status      int
	respBody    string
	gotAuth     string
	gotPath     string
	gotMessage  map[string]any
	assertion   string
}

func (f *fakeGoogle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/token" {
		_ = r.ParseForm()
		if r.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			f.t.Errorf("grant_type = %q", r.PostForm.Get("grant_type"))
		}
		f.assertion = r.PostForm.Get("assertion")
		n := f.tokenCalls.Add(1)
		if f.tokenStatus != 0 {
			w.WriteHeader(f.tokenStatus)
			_, _ = io.WriteString(w, f.tokenBody)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at-" + strconv.Itoa(int(n)), "expires_in": 3600, "token_type": "Bearer"})
		return
	}
	f.gotAuth = r.Header.Get("Authorization")
	f.gotPath = r.URL.Path
	b, _ := io.ReadAll(r.Body)
	var envelope map[string]map[string]any
	_ = json.Unmarshal(b, &envelope)
	f.gotMessage = envelope["message"]
	w.WriteHeader(f.status)
	_, _ = io.WriteString(w, f.respBody)
}

func newTestClient(t *testing.T) (*Client, *fakeGoogle, *time.Time) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeGoogle{t: t}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	c, err := NewClient(Config{ProjectID: "proj-1", ClientEmail: "relay@proj-1.iam.gserviceaccount.com", PrivateKey: key, TokenURL: srv.URL + "/token", BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }
	c.tokens.now = c.now
	return c, fake, &now
}

func fcmError(status, errorCode string, fields ...string) string {
	return fcmErrorMessage(status, errorCode, "x", fields...)
}

func fcmErrorMessage(status, errorCode, message string, fields ...string) string {
	details := []map[string]any{}
	if errorCode != "" {
		details = append(details, map[string]any{"@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError", "errorCode": errorCode})
	}
	if len(fields) > 0 {
		violations := []map[string]string{}
		for _, f := range fields {
			violations = append(violations, map[string]string{"field": f, "description": "bad"})
		}
		details = append(details, map[string]any{"@type": "type.googleapis.com/google.rpc.BadRequest", "fieldViolations": violations})
	}
	b, _ := json.Marshal(map[string]any{"error": map[string]any{"code": 400, "message": message, "status": status, "details": details}})
	return string(b)
}

func TestClientSendClassification(t *testing.T) {
	c, fake, now := newTestClient(t)
	payload := []byte(`{"data":{"title":"T","message":"B","tag":"d-1"}}`)
	cases := []struct {
		name       string
		status     int
		body       string
		want       push.Outcome
		wantReason string
	}{
		{"sent", 200, `{"name":"projects/proj-1/messages/123"}`, push.OutcomeSent, ""},
		{"unregistered", 404, fcmError("NOT_FOUND", "UNREGISTERED"), push.OutcomeInvalidToken, "UNREGISTERED"},
		// A wrong Firebase project is a relay config error: fail, never delete installations.
		{"sender mismatch", 403, fcmError("PERMISSION_DENIED", "SENDER_ID_MISMATCH"), push.OutcomeFailed, "SENDER_ID_MISMATCH"},
		// The shape FCM actually returns for a malformed token: no field violations.
		{"bad token", 400, fcmErrorMessage("INVALID_ARGUMENT", "INVALID_ARGUMENT", invalidTokenMessage), push.OutcomeInvalidToken, "INVALID_ARGUMENT"},
		{"bad token field", 400, fcmError("INVALID_ARGUMENT", "INVALID_ARGUMENT", "message.token"), push.OutcomeInvalidToken, "INVALID_ARGUMENT"},
		{"bad payload", 400, fcmError("INVALID_ARGUMENT", "INVALID_ARGUMENT", "message.data[0].value"), push.OutcomeFailed, "INVALID_ARGUMENT"},
		{"bad argument", 400, fcmError("INVALID_ARGUMENT", "INVALID_ARGUMENT"), push.OutcomeFailed, "INVALID_ARGUMENT"},
		{"quota", 429, fcmError("RESOURCE_EXHAUSTED", "QUOTA_EXCEEDED"), push.OutcomeRetry, "QUOTA_EXCEEDED"},
		{"unavailable", 503, fcmError("UNAVAILABLE", "UNAVAILABLE"), push.OutcomeRetry, "UNAVAILABLE"},
		{"internal", 500, fcmError("INTERNAL", "INTERNAL"), push.OutcomeRetry, "INTERNAL"},
		{"bad gateway", 502, "<html>", push.OutcomeRetry, ""},
		{"unauthenticated", 401, fcmError("UNAUTHENTICATED", ""), push.OutcomeRetry, "UNAUTHENTICATED"},
		{"wrong project", 404, fcmError("NOT_FOUND", ""), push.OutcomeFailed, "NOT_FOUND"},
	}
	for _, tc := range cases {
		fake.status, fake.respBody = tc.status, tc.body
		res, err := c.Send(t.Context(), push.Notification{DeviceToken: "tok:AbC_1-2", Payload: payload, CollapseID: "d-1", Expiration: now.Add(time.Hour)})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if res.Outcome != tc.want || res.StatusCode != tc.status || res.Reason != tc.wantReason {
			t.Errorf("%s: got %+v", tc.name, res)
		}
		if tc.status == 200 && res.ID != "projects/proj-1/messages/123" {
			t.Errorf("%s: id = %q", tc.name, res.ID)
		}
	}
	if fake.gotPath != "/v1/projects/proj-1/messages:send" {
		t.Errorf("path %q", fake.gotPath)
	}
	if !strings.HasPrefix(fake.gotAuth, "Bearer at-") {
		t.Errorf("auth %q", fake.gotAuth)
	}
	m := fake.gotMessage
	android, _ := m["android"].(map[string]any)
	data, _ := m["data"].(map[string]any)
	// No collapse_key: FCM would keep only four distinct alerts for an offline device.
	_, hasCollapseKey := android["collapse_key"]
	if m["token"] != "tok:AbC_1-2" || android["priority"] != "HIGH" || hasCollapseKey || android["ttl"] != "3600s" ||
		data["tag"] != "d-1" || m["notification"] != nil {
		t.Errorf("unexpected message %v", m)
	}
}

func TestAccessTokenCachedAndRefreshed(t *testing.T) {
	c, fake, now := newTestClient(t)
	fake.status, fake.respBody = 200, `{"name":"n"}`
	send := func() {
		t.Helper()
		if _, err := c.Send(t.Context(), push.Notification{DeviceToken: "t", Payload: []byte(`{"data":{}}`)}); err != nil {
			t.Fatal(err)
		}
	}
	send()
	send()
	if fake.tokenCalls.Load() != 1 {
		t.Fatalf("token should be cached, calls=%d", fake.tokenCalls.Load())
	}
	if fake.assertion == "" {
		t.Fatal("assertion not sent")
	}
	// Refreshed 5 minutes before the 1h expiry.
	*now = now.Add(56 * time.Minute)
	send()
	if fake.tokenCalls.Load() != 2 {
		t.Fatalf("token should refresh near expiry, calls=%d", fake.tokenCalls.Load())
	}
	// A 401 drops the cached token so the next send fetches a fresh one.
	fake.status, fake.respBody = 401, fcmError("UNAUTHENTICATED", "")
	send()
	fake.status, fake.respBody = 200, `{"name":"n"}`
	send()
	if fake.tokenCalls.Load() != 3 {
		t.Fatalf("401 should force a token refresh, calls=%d", fake.tokenCalls.Load())
	}
}

func TestTokenExchangeFailureRetries(t *testing.T) {
	c, fake, _ := newTestClient(t)
	fake.status, fake.respBody = 200, `{"name":"n"}`
	n := push.Notification{DeviceToken: "t", Payload: []byte(`{"data":{}}`)}

	fake.tokenStatus, fake.tokenBody = 400, `{"error":"invalid_grant","error_description":"`+strings.Repeat("x", 1000)+`"}`
	res, err := c.Send(t.Context(), n)
	if err == nil || res.Outcome != push.OutcomeRetry || fake.gotPath != "" {
		t.Fatalf("got %+v, %v", res, err)
	}
	// The error lands in logs and last_error, so Google's response body is truncated.
	if !strings.Contains(err.Error(), "invalid_grant") || len(err.Error()) > maxErrorBody+64 {
		t.Fatalf("error not truncated: %d bytes", len(err.Error()))
	}

	fake.tokenStatus, fake.tokenBody = 200, `{"token_type":"Bearer"}`
	if res, err = c.Send(t.Context(), n); err == nil || res.Outcome != push.OutcomeRetry {
		t.Fatalf("malformed token response: %+v, %v", res, err)
	}

	// Nothing was cached, so the next send exchanges again and succeeds.
	fake.tokenStatus = 0
	if res, err = c.Send(t.Context(), n); err != nil || res.Outcome != push.OutcomeSent {
		t.Fatalf("recovery: %+v, %v", res, err)
	}
	if fake.tokenCalls.Load() != 3 {
		t.Fatalf("token calls = %d", fake.tokenCalls.Load())
	}
}

func TestClientAudienceDefaultsToTokenURL(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{ProjectID: "p", ClientEmail: "e", PrivateKey: key, TokenURL: "https://t.example/token", BaseURL: "https://b.example"}
	c, err := NewClient(cfg)
	if err != nil || c.tokens.audience != cfg.TokenURL {
		t.Fatalf("default audience: %v %q", err, c.tokens.audience)
	}
	cfg.TokenAudience = "https://oauth2.googleapis.com/token"
	if c, err = NewClient(cfg); err != nil || c.tokens.audience != cfg.TokenAudience || c.tokens.tokenURL != cfg.TokenURL {
		t.Fatalf("explicit audience: %v %q", err, c.tokens.audience)
	}
}

func TestInvalidStoredPayloadFailsWithoutSending(t *testing.T) {
	c, fake, _ := newTestClient(t)
	res, err := c.Send(t.Context(), push.Notification{DeviceToken: "t", Payload: []byte(`{"aps":{}}`)})
	if err != nil || res.Outcome != push.OutcomeFailed {
		t.Fatalf("got %+v, %v", res, err)
	}
	if fake.tokenCalls.Load() != 0 || fake.gotPath != "" {
		t.Fatal("nothing should have been sent")
	}
}
