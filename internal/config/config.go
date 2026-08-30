// Package config loads relay configuration from an optional YAML file and the environment.
//
// Precedence: built-in defaults < YAML file < environment variables.
package config

import (
	"bytes"
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
		if v := strings.TrimSpace(getenv(env)); v != "" {
			return v
		}
		if strings.TrimSpace(fileVal) != "" {
			return strings.TrimSpace(fileVal)
		}
		return def
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

	r := &resolver{cfg: cfg, file: f, getenv: getenv, readFile: readFile, str: str}
	r.encryptionKey()
	r.durations()
	r.integers()
	r.flagsAndLogging()
	r.apns()
	if len(r.errs) > 0 {
		return nil, errors.Join(r.errs...)
	}
	return cfg, nil
}

type resolver struct {
	cfg      *Config
	file     File
	getenv   func(string) string
	readFile func(string) ([]byte, error)
	str      func(env, fileVal, def string) string
	errs     []error
}

func (r *resolver) failf(format string, args ...any) {
	r.errs = append(r.errs, fmt.Errorf(format, args...))
}

// encryptionKey resolves env value > env file > yaml value > yaml file.
func (r *resolver) encryptionKey() {
	keyRaw := r.str("RELAY_ENCRYPTION_KEY", r.file.EncryptionKey, "")
	if keyRaw == "" {
		if keyFile := r.str("RELAY_ENCRYPTION_KEY_FILE", r.file.EncryptionKeyFile, ""); keyFile != "" {
			b, err := r.readFile(keyFile)
			if err != nil {
				r.failf("encryption key file: %w", err)
			}
			keyRaw = string(b)
		}
	}
	key, err := decodeKey(keyRaw)
	if err != nil {
		r.failf("encryption_key / RELAY_ENCRYPTION_KEY: %w", err)
	}
	r.cfg.EncryptionKey = key
}

func (r *resolver) durations() {
	for _, it := range []struct {
		env, file, name string
		dst             *time.Duration
	}{
		{"RELAY_MAX_ENVELOPE_AGE", r.file.MaxEnvelopeAge, "max_envelope_age", &r.cfg.MaxEnvelopeAge},
		{"RELAY_RETENTION", r.file.Retention, "retention", &r.cfg.Retention},
	} {
		v := r.str(it.env, it.file, "")
		if v == "" {
			continue
		}
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			r.failf("%s: invalid duration %q", it.name, v)
			continue
		}
		*it.dst = d
	}
}

func (r *resolver) integers() {
	if v, ok := intValue(r.getenv("RELAY_MAX_BODY_BYTES"), r.file.MaxBodyBytes); ok {
		if v < 1024 {
			r.failf("max_body_bytes: must be at least 1024")
		} else {
			r.cfg.MaxBodyBytes = v
		}
	} else if r.getenv("RELAY_MAX_BODY_BYTES") != "" {
		r.failf("RELAY_MAX_BODY_BYTES: invalid value")
	}
	for _, it := range []struct {
		env  string
		file *int
		dst  *int
		min  int
		max  int
	}{
		{"RELAY_WORKERS", r.file.Workers, &r.cfg.Workers, 1, 256},
		{"RELAY_MAX_ATTEMPTS", r.file.MaxAttempts, &r.cfg.MaxAttempts, 1, 50},
		{"RELAY_RATE_LIMIT_IP_PER_MINUTE", r.file.RateLimits.IPPerMinute, &r.cfg.RateLimits.IPPerMinute, 1, 1 << 30},
		{"RELAY_RATE_LIMIT_CHANNEL_PER_MINUTE", r.file.RateLimits.ChannelPerMinute, &r.cfg.RateLimits.ChannelPerMinute, 1, 1 << 30},
		{"RELAY_RATE_LIMIT_INSTALLATION_PER_MINUTE", r.file.RateLimits.InstallationPerMinute, &r.cfg.RateLimits.InstallationPerMinute, 1, 1 << 30},
	} {
		v, ok := intValue(r.getenv(it.env), ptrInt64FromInt(it.file))
		if !ok {
			if r.getenv(it.env) != "" {
				r.failf("%s: invalid value", it.env)
			}
			continue
		}
		if v < int64(it.min) || v > int64(it.max) {
			r.failf("%s: must be between %d and %d", it.env, it.min, it.max)
			continue
		}
		*it.dst = int(v)
	}
}

func (r *resolver) flagsAndLogging() {
	if v := r.getenv("RELAY_TRUST_PROXY_HEADERS"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			r.failf("RELAY_TRUST_PROXY_HEADERS: invalid value %q", v)
		}
		r.cfg.TrustProxyHeaders = b
	} else if r.file.TrustProxyHeaders != nil {
		r.cfg.TrustProxyHeaders = *r.file.TrustProxyHeaders
	}
	if v := r.str("RELAY_LOG_LEVEL", r.file.Log.Level, ""); v != "" {
		var lvl slog.Level
		if err := lvl.UnmarshalText([]byte(v)); err != nil {
			r.failf("log.level: invalid value %q", v)
		}
		r.cfg.LogLevel = lvl
	}
	if r.cfg.LogFormat != "json" && r.cfg.LogFormat != "text" {
		r.failf("log.format: must be json or text")
	}
}

func (r *resolver) apns() {
	switch r.cfg.APNS.Mode {
	case APNSModeLive:
		if r.cfg.APNS.KeyID == "" {
			r.failf("apns.key_id / APNS_KEY_ID is required")
		}
		if r.cfg.APNS.TeamID == "" {
			r.failf("apns.team_id / APNS_TEAM_ID is required")
		}
		pk, err := loadAPNSKey(r.file, r.getenv, r.readFile)
		if err != nil {
			r.errs = append(r.errs, err)
		}
		r.cfg.APNS.PrivateKey = pk
	case APNSModeLog:
	default:
		r.failf("apns.mode: must be %q or %q", APNSModeLive, APNSModeLog)
	}
	if r.cfg.APNS.Topic == "" {
		r.failf("apns.topic must not be empty")
	}
}

func ptrInt64FromInt(p *int) *int64 {
	if p == nil {
		return nil
	}
	v := int64(*p)
	return &v
}

// intValue returns env (parsed) if set, else the file value if set. ok=false when neither
// is usable; callers distinguish "unset" from "invalid" by checking env themselves.
func intValue(env string, file *int64) (int64, bool) {
	if strings.TrimSpace(env) != "" {
		n, err := strconv.ParseInt(strings.TrimSpace(env), 10, 64)
		if err != nil {
			return 0, false
		}
		return n, true
	}
	if file != nil {
		return *file, true
	}
	return 0, false
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

func loadAPNSKey(f File, getenv func(string) string, readFile func(string) ([]byte, error)) (*ecdsa.PrivateKey, error) {
	var pemBytes []byte
	switch {
	case getenv("APNS_KEY_P8") != "":
		pemBytes = []byte(strings.ReplaceAll(getenv("APNS_KEY_P8"), `\n`, "\n"))
	case getenv("APNS_KEY_FILE") != "":
		b, err := readFile(getenv("APNS_KEY_FILE"))
		if err != nil {
			return nil, fmt.Errorf("APNS_KEY_FILE: %w", err)
		}
		pemBytes = b
	case strings.TrimSpace(f.APNS.Key) != "":
		pemBytes = []byte(f.APNS.Key)
	case strings.TrimSpace(f.APNS.KeyFile) != "":
		b, err := readFile(strings.TrimSpace(f.APNS.KeyFile))
		if err != nil {
			return nil, fmt.Errorf("apns.key_file: %w", err)
		}
		pemBytes = b
	default:
		return nil, errors.New("apns.key / apns.key_file (or APNS_KEY_P8 / APNS_KEY_FILE) is required")
	}
	return ParseP8(pemBytes)
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
