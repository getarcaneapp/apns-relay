package apns

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestProviderTokenIsValidES256AndCached(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Unix(1_700_000_000, 0)
	p := &tokenProvider{keyID: "KID", teamID: "TEAM", key: key, now: func() time.Time { return now }}
	tok, err := p.Token()
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("bad jwt %q", tok)
	}
	var header map[string]string
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	_ = json.Unmarshal(hb, &header)
	if header["alg"] != "ES256" || header["kid"] != "KID" {
		t.Fatalf("bad header %v", header)
	}
	var claims map[string]any
	cb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	_ = json.Unmarshal(cb, &claims)
	if claims["iss"] != "TEAM" || int64(claims["iat"].(float64)) != now.Unix() {
		t.Fatalf("bad claims %v", claims)
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r, s := ParseJWTSignature(sig)
	if !ecdsa.Verify(&key.PublicKey, digest[:], r, s) {
		t.Fatal("signature does not verify")
	}
	if again, _ := p.Token(); again != tok {
		t.Fatal("token should be cached")
	}
	now = now.Add(51 * time.Minute)
	if again, _ := p.Token(); again == tok {
		t.Fatal("token should rotate after 50 minutes")
	}
}

func TestClientSendClassification(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var status int
	var reason string
	var gotHeaders http.Header
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		gotPath = r.URL.Path
		w.Header().Set("apns-id", "id-1")
		w.WriteHeader(status)
		if reason != "" {
			_ = json.NewEncoder(w).Encode(map[string]string{"reason": reason})
		}
	}))
	defer srv.Close()
	c, err := NewClient(Config{KeyID: "K", TeamID: "T", Topic: "com.example.app", PrivateKey: key, SandboxURL: srv.URL, ProductionURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		status int
		reason string
		want   Outcome
	}{
		{200, "", OutcomeSent},
		{410, "Unregistered", OutcomeInvalidToken},
		{400, "BadDeviceToken", OutcomeInvalidToken},
		{403, "ExpiredProviderToken", OutcomeRetry},
		{429, "TooManyRequests", OutcomeRetry},
		{503, "ServiceUnavailable", OutcomeRetry},
		{400, "PayloadTooLarge", OutcomeFailed},
		{400, "TopicDisallowed", OutcomeFailed},
	}
	for _, tc := range cases {
		status, reason = tc.status, tc.reason
		res, sendErr := c.Send(t.Context(), Notification{DeviceToken: "abcd", Environment: EnvironmentSandbox, Payload: []byte(`{}`), CollapseID: "evt", Expiration: time.Now().Add(time.Hour)})
		if sendErr != nil {
			t.Fatalf("%d %s: %v", tc.status, tc.reason, sendErr)
		}
		if res.Outcome != tc.want || res.StatusCode != tc.status || res.Reason != tc.reason {
			t.Errorf("%d %s: got %+v", tc.status, tc.reason, res)
		}
	}
	if gotPath != "/3/device/abcd" {
		t.Errorf("path %q", gotPath)
	}
	for k, want := range map[string]string{"Apns-Topic": "com.example.app", "Apns-Push-Type": "alert", "Apns-Priority": "10", "Apns-Collapse-Id": "evt"} {
		if gotHeaders.Get(k) != want {
			t.Errorf("header %s = %q, want %q", k, gotHeaders.Get(k), want)
		}
	}
	if !strings.HasPrefix(gotHeaders.Get("Authorization"), "bearer ") {
		t.Error("missing bearer token")
	}
}
