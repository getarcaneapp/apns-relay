package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
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
	if cfg.ListenAddr != DefaultListenAddr || cfg.Workers != DefaultWorkers || cfg.APNS.Topic != DefaultAPNSTopic {
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
