// Package config loads relay configuration from an optional YAML file and the environment.
//
// Precedence: built-in defaults < YAML file < environment variables.
package config

import (
	"bytes"
	"cmp"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	kit "go.getarcane.app/kit/pkg"
	"go.yaml.in/yaml/v4"
)

// Defaults applied when neither the file nor the environment sets a value.
const (
	DefaultListenAddr     = ":3554"
	DefaultDatabasePath   = "./data/relay.db"
	DefaultMaxEnvelopeAge = 5 * time.Minute
	DefaultMaxBodyBytes   = 64 * 1024
	DefaultWorkers        = 8
	DefaultMaxAttempts    = 8
	DefaultRetention      = 24 * time.Hour
	DefaultAPNSTopic      = "com.getarcaneapp.ios.mobile"

	// APNSSandboxURL is Apple's development APNs host.
	APNSSandboxURL = "https://api.sandbox.push.apple.com"
	// APNSProductionURL is Apple's production APNs host.
	APNSProductionURL = "https://api.push.apple.com"
)

// APNSMode controls how deliveries leave the relay.
type APNSMode string

const (
	// APNSModeLive sends to Apple.
	APNSModeLive APNSMode = "live"
	// APNSModeLog logs deliveries instead of sending them (local development only).
	APNSModeLog APNSMode = "log"
)

// File is the YAML schema. All fields are optional; unset fields keep defaults.
type File struct {
	Listen            string `yaml:"listen"`
	DatabasePath      string `yaml:"database_path"`
	EncryptionKey     string `yaml:"encryption_key"`
	EncryptionKeyFile string `yaml:"encryption_key_file"`
	MaxEnvelopeAge    string `yaml:"max_envelope_age"`
	MaxBodyBytes      *int64 `yaml:"max_body_bytes"`
	Workers           *int   `yaml:"workers"`
	MaxAttempts       *int   `yaml:"max_attempts"`
	Retention         string `yaml:"retention"`
	TrustProxyHeaders *bool  `yaml:"trust_proxy_headers"`
	Log               struct {
		Level  string `yaml:"level"`
		Format string `yaml:"format"`
	} `yaml:"log"`
	RateLimits struct {
		IPPerMinute           *int `yaml:"ip_per_minute"`
		ChannelPerMinute      *int `yaml:"channel_per_minute"`
		InstallationPerMinute *int `yaml:"installation_per_minute"`
	} `yaml:"rate_limits"`
	APNS struct {
		Mode          string `yaml:"mode"`
		KeyID         string `yaml:"key_id"`
		TeamID        string `yaml:"team_id"`
		Topic         string `yaml:"topic"`
		Key           string `yaml:"key"`
		KeyFile       string `yaml:"key_file"`
		SandboxURL    string `yaml:"sandbox_url"`
		ProductionURL string `yaml:"production_url"`
	} `yaml:"apns"`
}

// APNS holds Apple Push Notification service credentials.
type APNS struct {
	Mode          APNSMode
	KeyID         string
	TeamID        string
	Topic         string
	PrivateKey    *ecdsa.PrivateKey
	SandboxURL    string
	ProductionURL string
}

// RateLimits are token-bucket parameters per minute.
type RateLimits struct {
	IPPerMinute           int
	ChannelPerMinute      int
	InstallationPerMinute int
}

// Config is the fully resolved relay configuration.
type Config struct {
	ListenAddr        string
	DatabasePath      string
	EncryptionKey     []byte
	MaxEnvelopeAge    time.Duration
	MaxBodyBytes      int64
	Workers           int
	MaxAttempts       int
	Retention         time.Duration
	TrustProxyHeaders bool
	LogLevel          slog.Level
	LogFormat         string
	RateLimits        RateLimits
	APNS              APNS
}

// Load reads the YAML file at path (if non-empty) and applies environment overrides.
func Load(path string) (*Config, error) {
	var file File
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config file: %w", err)
		}
		f, err := ParseFile(b)
		if err != nil {
			return nil, fmt.Errorf("parse config file %s: %w", path, err)
		}
		file = *f
	}
	return resolve(file, os.Getenv, os.ReadFile)
}

// ParseFile decodes YAML strictly (unknown keys are errors).
func ParseFile(b []byte) (*File, error) {
	var f File
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		if errors.Is(err, io.EOF) {
			return &f, nil
		}
		return nil, err
	}
	return &f, nil
}

// resolve merges defaults, file and env. Env variable names mirror YAML keys with a
// RELAY_ prefix (APNS_ prefix for the apns block).
func resolve(f File, getenv func(string) string, readFile func(string) ([]byte, error)) (*Config, error) {
	str := func(env, fileVal, def string) string {
		return cmp.Or(strings.TrimSpace(getenv(env)), strings.TrimSpace(fileVal), def)
	}
	cfg := &Config{
		ListenAddr:     str("RELAY_LISTEN_ADDR", f.Listen, DefaultListenAddr),
		DatabasePath:   str("RELAY_DATABASE_PATH", f.DatabasePath, DefaultDatabasePath),
		MaxEnvelopeAge: DefaultMaxEnvelopeAge,
		MaxBodyBytes:   DefaultMaxBodyBytes,
		Workers:        DefaultWorkers,
		MaxAttempts:    DefaultMaxAttempts,
		Retention:      DefaultRetention,
		LogLevel:       slog.LevelInfo,
		LogFormat:      str("RELAY_LOG_FORMAT", f.Log.Format, "json"),
		RateLimits: RateLimits{
			IPPerMinute:           60,
			ChannelPerMinute:      600,
			InstallationPerMinute: 60,
		},
		APNS: APNS{
			Mode:          APNSMode(str("APNS_MODE", f.APNS.Mode, string(APNSModeLive))),
			KeyID:         str("APNS_KEY_ID", f.APNS.KeyID, ""),
			TeamID:        str("APNS_TEAM_ID", f.APNS.TeamID, ""),
			Topic:         str("APNS_TOPIC", f.APNS.Topic, DefaultAPNSTopic),
			SandboxURL:    str("APNS_SANDBOX_URL", f.APNS.SandboxURL, APNSSandboxURL),
			ProductionURL: str("APNS_PRODUCTION_URL", f.APNS.ProductionURL, APNSProductionURL),
		},
	}

	var errs []error
	failf := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	if keyRaw, err := secretValue(getenv, readFile, "RELAY_ENCRYPTION_KEY", "RELAY_ENCRYPTION_KEY_FILE", f.EncryptionKey, f.EncryptionKeyFile); err != nil {
		failf("encryption key file: %w", err)
	} else if cfg.EncryptionKey, err = decodeKey(keyRaw); err != nil {
		failf("encryption_key / RELAY_ENCRYPTION_KEY: %w", err)
	}

	for _, it := range []struct {
		env, file, name string
		dst             *time.Duration
	}{
		{"RELAY_MAX_ENVELOPE_AGE", f.MaxEnvelopeAge, "max_envelope_age", &cfg.MaxEnvelopeAge},
		{"RELAY_RETENTION", f.Retention, "retention", &cfg.Retention},
	} {
		v := str(it.env, it.file, "")
		if v == "" {
			continue
		}
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			failf("%s: invalid duration %q", it.name, v)
			continue
		}
		*it.dst = d
	}

	errs = append(errs,
		intSetting(getenv, "RELAY_MAX_BODY_BYTES", f.MaxBodyBytes, &cfg.MaxBodyBytes, 1024, 1<<30),
		intSetting(getenv, "RELAY_WORKERS", f.Workers, &cfg.Workers, 1, 256),
		intSetting(getenv, "RELAY_MAX_ATTEMPTS", f.MaxAttempts, &cfg.MaxAttempts, 1, 50),
		intSetting(getenv, "RELAY_RATE_LIMIT_IP_PER_MINUTE", f.RateLimits.IPPerMinute, &cfg.RateLimits.IPPerMinute, 1, 1<<30),
		intSetting(getenv, "RELAY_RATE_LIMIT_CHANNEL_PER_MINUTE", f.RateLimits.ChannelPerMinute, &cfg.RateLimits.ChannelPerMinute, 1, 1<<30),
		intSetting(getenv, "RELAY_RATE_LIMIT_INSTALLATION_PER_MINUTE", f.RateLimits.InstallationPerMinute, &cfg.RateLimits.InstallationPerMinute, 1, 1<<30),
	)

	cfg.TrustProxyHeaders = kit.FromPtr(f.TrustProxyHeaders)
	if v := getenv("RELAY_TRUST_PROXY_HEADERS"); v != "" {
		b, ok := kit.ParseBool(v)
		if !ok {
			failf("RELAY_TRUST_PROXY_HEADERS: invalid value %q", v)
		}
		cfg.TrustProxyHeaders = b
	}
	if v := str("RELAY_LOG_LEVEL", f.Log.Level, ""); v != "" {
		if err := cfg.LogLevel.UnmarshalText([]byte(v)); err != nil {
			failf("log.level: invalid value %q", v)
		}
	}
	if cfg.LogFormat != "json" && cfg.LogFormat != "text" {
		failf("log.format: must be json or text")
	}

	switch cfg.APNS.Mode {
	case APNSModeLive:
		if cfg.APNS.KeyID == "" {
			failf("apns.key_id / APNS_KEY_ID is required")
		}
		if cfg.APNS.TeamID == "" {
			failf("apns.team_id / APNS_TEAM_ID is required")
		}
		keyPEM, err := secretValue(getenv, readFile, "APNS_KEY_P8", "APNS_KEY_FILE", f.APNS.Key, f.APNS.KeyFile)
		switch {
		case err != nil:
			failf("apns.key_file / APNS_KEY_FILE: %w", err)
		case keyPEM == "":
			failf("apns.key / apns.key_file (or APNS_KEY_P8 / APNS_KEY_FILE) is required")
		default:
			cfg.APNS.PrivateKey, err = ParseP8([]byte(strings.ReplaceAll(keyPEM, `\n`, "\n")))
			errs = append(errs, err)
		}
	case APNSModeLog:
	default:
		failf("apns.mode: must be %q or %q", APNSModeLive, APNSModeLog)
	}
	if cfg.APNS.Topic == "" {
		failf("apns.topic must not be empty")
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return cfg, nil
}

// secretValue returns an inline value or the contents of a file path; the env pair overrides the YAML pair.
func secretValue(getenv func(string) string, readFile func(string) ([]byte, error), env, envFile, yamlValue, yamlFile string) (string, error) {
	value, file := strings.TrimSpace(getenv(env)), strings.TrimSpace(getenv(envFile))
	if value == "" && file == "" {
		value, file = strings.TrimSpace(yamlValue), strings.TrimSpace(yamlFile)
	}
	if value != "" || file == "" {
		return value, nil
	}
	b, err := readFile(file)
	return string(b), err
}

// intSetting applies the env value, or else the YAML value, to dst when it lies within [lo, hi].
func intSetting[T int | int64](getenv func(string) string, env string, file, dst *T, lo, hi T) error {
	var v int64
	switch raw := strings.TrimSpace(getenv(env)); {
	case raw != "":
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return fmt.Errorf("%s: invalid value", env)
		}
		v = n
	case file != nil:
		v = int64(*file)
	default:
		return nil
	}
	if v < int64(lo) || v > int64(hi) {
		return fmt.Errorf("%s: must be between %d and %d", env, lo, hi)
	}
	*dst = T(v)
	return nil
}

// decodeKey accepts a 32-byte key encoded as hex or base64 (std or url, padded or not).
func decodeKey(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("missing (32 random bytes, hex or base64)")
	}
	if b, err := hex.DecodeString(raw); err == nil && len(b) == 32 {
		return b, nil
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(raw); err == nil && len(b) == 32 {
			return b, nil
		}
	}
	return nil, errors.New("must decode to exactly 32 bytes (hex or base64)")
}

// ParseP8 parses an APNs auth key (.p8, PKCS#8 PEM) into an ECDSA P-256 private key.
// Apple only accepts ES256 provider tokens, so this is the only key type supported.
func ParseP8(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("APNs key: no PEM block found")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("APNs key: %w", err)
	}
	pk, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("APNs key: not an ECDSA private key (APNs requires ES256 / P-256)")
	}
	return pk, nil
}
