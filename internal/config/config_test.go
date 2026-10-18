package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"maps"
	"os"
	"strings"
	"testing"
)

func env(overrides map[string]string) func(string) string {
	base := map[string]string{
		"RELAY_ENCRYPTION_KEY": hex.EncodeToString(make([]byte, 32)),
		"APNS_MODE":            "log",
	}
	maps.Copy(base, overrides)
	return func(k string) string { return base[k] }
}

func noFiles(string) ([]byte, error) { return nil, errors.New("no files") }

func TestResolveDefaults(t *testing.T) {
	cfg, err := resolve(File{}, env(nil), noFiles)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if cfg.ListenAddr != DefaultListenAddr || cfg.Workers != DefaultWorkers || cfg.APNS.Topic != DefaultAPNSTopic ||
		cfg.FCM.Mode != FCMModeDisabled || cfg.FCM.Enabled() {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}

func TestResolveRequiresAPNSCredentialsInLiveMode(t *testing.T) {
	_, err := resolve(File{}, env(map[string]string{"APNS_MODE": "live"}), noFiles)
	if err == nil {
		t.Fatal("expected error")
	}
	for _, want := range []string{"key_id", "team_id", "apns.key"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error missing %s: %v", want, err)
		}
	}
}

func TestResolveLiveModeParsesInlineKey(t *testing.T) {
	pk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(pk)
	p8 := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	cfg, err := resolve(File{}, env(map[string]string{
		"APNS_MODE":    "live",
		"APNS_KEY_ID":  "ABC123",
		"APNS_TEAM_ID": "TEAM1",
		"APNS_KEY_P8":  strings.ReplaceAll(p8, "\n", `\n`),
	}), noFiles)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !cfg.APNS.PrivateKey.Equal(pk) {
		t.Fatal("parsed key mismatch")
	}
}

func TestYAMLFileWithEnvOverride(t *testing.T) {
	pk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(pk)
	keyPath := t.TempDir() + "/AuthKey.p8"
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	yamlSrc := `
listen: ":9999"
database_path: /tmp/relay.db
encryption_key: ` + hex.EncodeToString(make([]byte, 32)) + `
workers: 3
max_envelope_age: 2m
trust_proxy_headers: true
log:
  level: debug
  format: text
rate_limits:
  channel_per_minute: 42
apns:
  mode: live
  key_id: KEY1
  team_id: TEAM1
  key_file: ` + keyPath + `
`
	f, err := ParseFile([]byte(yamlSrc))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := resolve(*f, func(k string) string {
		if k == "RELAY_WORKERS" {
			return "5"
		}
		return ""
	}, os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddr != ":9999" || cfg.Workers != 5 || cfg.MaxEnvelopeAge.Minutes() != 2 || !cfg.TrustProxyHeaders ||
		cfg.LogFormat != "text" || cfg.RateLimits.ChannelPerMinute != 42 || cfg.APNS.KeyID != "KEY1" || cfg.APNS.PrivateKey == nil {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestYAMLRejectsUnknownKeys(t *testing.T) {
	if _, err := ParseFile([]byte("listen: ':1'\nbogus: true\n")); err == nil {
		t.Fatal("expected unknown key error")
	}
	if f, err := ParseFile(nil); err != nil || f == nil {
		t.Fatalf("empty file should parse: %v", err)
	}
}

func TestDecodeKeyFormats(t *testing.T) {
	for _, in := range []string{
		hex.EncodeToString(make([]byte, 32)),
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	} {
		if _, err := decodeKey(in); err != nil {
			t.Errorf("decodeKey(%q): %v", in, err)
		}
	}
	if _, err := decodeKey("short"); err == nil {
		t.Error("expected error for short key")
	}
}

func serviceAccountJSON(t *testing.T, projectID string) (string, *rsa.PrivateKey) {
	t.Helper()
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(pk)
	b, _ := json.Marshal(map[string]string{
		"type":         "service_account",
		"project_id":   projectID,
		"client_email": "relay@" + projectID + ".iam.gserviceaccount.com",
		"private_key":  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"token_uri":    "https://oauth2.googleapis.com/token",
	})
	return string(b), pk
}

func TestResolveFCMLiveModeRequiresServiceAccount(t *testing.T) {
	_, err := resolve(File{}, env(map[string]string{"FCM_MODE": "live"}), noFiles)
	if err == nil || !strings.Contains(err.Error(), "fcm.service_account") {
		t.Fatalf("expected service account error, got %v", err)
	}
	_, err = resolve(File{}, env(map[string]string{"FCM_MODE": "loud"}), noFiles)
	if err == nil || !strings.Contains(err.Error(), "fcm.mode") {
		t.Fatalf("expected mode error, got %v", err)
	}
}

func TestResolveFCMLiveModeParsesInlineServiceAccount(t *testing.T) {
	sa, pk := serviceAccountJSON(t, "proj-1")
	cfg, err := resolve(File{}, env(map[string]string{"FCM_MODE": "live", "FCM_SERVICE_ACCOUNT_JSON": sa}), noFiles)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// Failure messages name fields rather than %+v so the private key never reaches test logs.
	if !cfg.FCM.Enabled() || cfg.FCM.ProjectID != "proj-1" || cfg.FCM.ClientEmail != "relay@proj-1.iam.gserviceaccount.com" ||
		cfg.FCM.TokenURL != FCMTokenURL || cfg.FCM.TokenAudience != FCMTokenURL || cfg.FCM.BaseURL != FCMBaseURL || !cfg.FCM.PrivateKey.Equal(pk) {
		t.Fatalf("unexpected fcm config: mode=%s project=%s email=%s tokenURL=%s aud=%s base=%s keyMatches=%t",
			cfg.FCM.Mode, cfg.FCM.ProjectID, cfg.FCM.ClientEmail, cfg.FCM.TokenURL, cfg.FCM.TokenAudience, cfg.FCM.BaseURL, cfg.FCM.PrivateKey.Equal(pk))
	}
	// FCM_PROJECT_ID overrides the service account's project.
	cfg, err = resolve(File{}, env(map[string]string{"FCM_MODE": "live", "FCM_SERVICE_ACCOUNT_JSON": sa, "FCM_PROJECT_ID": "proj-2"}), noFiles)
	if err != nil || cfg.FCM.ProjectID != "proj-2" {
		t.Fatalf("project override: %v", err)
	}
	// FCM_TOKEN_URL changes where tokens are fetched, not the audience Google checks.
	cfg, err = resolve(File{}, env(map[string]string{"FCM_MODE": "live", "FCM_SERVICE_ACCOUNT_JSON": sa, "FCM_TOKEN_URL": "http://127.0.0.1:9/token"}), noFiles)
	if err != nil || cfg.FCM.TokenURL != "http://127.0.0.1:9/token" || cfg.FCM.TokenAudience != FCMTokenURL {
		t.Fatalf("token url override: %v", err)
	}
	// A service account without a project id needs one configured.
	noProject, _ := serviceAccountJSON(t, "")
	if _, err = resolve(File{}, env(map[string]string{"FCM_MODE": "live", "FCM_SERVICE_ACCOUNT_JSON": noProject}), noFiles); err == nil ||
		!strings.Contains(err.Error(), "project_id") {
		t.Fatalf("expected project id error, got %v", err)
	}
}

func TestYAMLFCMBlockFromFile(t *testing.T) {
	sa, _ := serviceAccountJSON(t, "proj-yaml")
	saPath := t.TempDir() + "/fcm.json"
	if err := os.WriteFile(saPath, []byte(sa), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := ParseFile([]byte("fcm:\n  mode: live\n  service_account_file: " + saPath + "\n  base_url: https://fcm.example\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := resolve(*f, env(nil), os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FCM.Mode != FCMModeLive || cfg.FCM.ProjectID != "proj-yaml" || cfg.FCM.BaseURL != "https://fcm.example" || cfg.FCM.PrivateKey == nil {
		t.Fatalf("unexpected fcm config: mode=%s project=%s base=%s hasKey=%t", cfg.FCM.Mode, cfg.FCM.ProjectID, cfg.FCM.BaseURL, cfg.FCM.PrivateKey != nil)
	}
}

func TestParseServiceAccountRejectsBadKeys(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(ec)
	ecJSON, _ := json.Marshal(map[string]string{"client_email": "a@b", "private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))})
	for name, in := range map[string]string{
		"not json":   "nope",
		"wrong type": `{"type":"authorized_user","client_email":"a@b"}`,
		"no email":   `{"private_key":"x"}`,
		"no pem":     `{"client_email":"a@b","private_key":"x"}`,
		"not rsa":    string(ecJSON),
	} {
		if _, err := ParseServiceAccount([]byte(in)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
