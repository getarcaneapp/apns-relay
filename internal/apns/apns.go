// Package apns sends alert pushes to Apple over HTTP/2 with token-based (JWT) auth.
package apns

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	kit "go.getarcane.app/kit/pkg"
)

// Environment selects the APNs host.
type Environment string

// APNs environments, chosen per installation from its aps-environment entitlement.
const (
	EnvironmentSandbox    Environment = "sandbox"
	EnvironmentProduction Environment = "production"
)

// ValidEnvironment reports whether e is a known environment.
func ValidEnvironment(e string) bool {
	return e == string(EnvironmentSandbox) || e == string(EnvironmentProduction)
}

// Notification is a single push request.
type Notification struct {
	DeviceToken string
	Environment Environment
	Payload     []byte
	CollapseID  string
	Expiration  time.Time
}

// Outcome classifies an APNs response for the delivery worker.
type Outcome int

const (
	// OutcomeSent means APNs accepted the notification.
	OutcomeSent Outcome = iota
	// OutcomeRetry means a transient failure; try again later.
	OutcomeRetry
	// OutcomeInvalidToken means the device token is dead; remove the installation.
	OutcomeInvalidToken
	// OutcomeFailed means a permanent, non-token failure.
	OutcomeFailed
)

// Result describes what APNs said.
type Result struct {
	Outcome    Outcome
	StatusCode int
	Reason     string
	APNSID     string
}

// Sender is implemented by the live client and the log-only client.
type Sender interface {
	Send(ctx context.Context, n Notification) (Result, error)
}

// Config for the live client.
type Config struct {
	KeyID         string
	TeamID        string
	Topic         string
	PrivateKey    *ecdsa.PrivateKey
	SandboxURL    string
	ProductionURL string
}

// Client sends to APNs using a persistent HTTP/2 connection pool.
type Client struct {
	cfg    Config
	http   *http.Client
	tokens *tokenProvider
}

// NewClient constructs a live client.
func NewClient(cfg Config) (*Client, error) {
	if cfg.PrivateKey == nil || cfg.KeyID == "" || cfg.TeamID == "" || cfg.Topic == "" {
		return nil, errors.New("apns: key, key id, team id and topic are required")
	}
	if cfg.SandboxURL == "" || cfg.ProductionURL == "" {
		return nil, errors.New("apns: sandbox and production URLs are required")
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       10 * time.Minute,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
	}
	return &Client{
		cfg:    cfg,
		http:   &http.Client{Transport: transport, Timeout: 30 * time.Second},
		tokens: &tokenProvider{keyID: cfg.KeyID, teamID: cfg.TeamID, key: cfg.PrivateKey, now: time.Now},
	}, nil
}

// Send delivers one notification.
func (c *Client) Send(ctx context.Context, n Notification) (Result, error) {
	base := kit.Ternary(n.Environment == EnvironmentSandbox, c.cfg.SandboxURL, c.cfg.ProductionURL)
	token, err := c.tokens.Token()
	if err != nil {
		return Result{Outcome: OutcomeRetry}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/3/device/"+n.DeviceToken, bytes.NewReader(n.Payload))
	if err != nil {
		return Result{Outcome: OutcomeFailed}, err
	}
	req.Header.Set("Authorization", "bearer "+token)
	req.Header.Set("Apns-Topic", c.cfg.Topic)
	req.Header.Set("Apns-Push-Type", "alert")
	req.Header.Set("Apns-Priority", "10")
	req.Header.Set("Content-Type", "application/json")
	if n.CollapseID != "" {
		req.Header.Set("Apns-Collapse-Id", n.CollapseID)
	}
	if !n.Expiration.IsZero() {
		req.Header.Set("Apns-Expiration", strconv.FormatInt(n.Expiration.Unix(), 10))
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return Result{Outcome: OutcomeRetry, Reason: "transport"}, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	res := Result{StatusCode: resp.StatusCode, APNSID: resp.Header.Get("Apns-Id")}
	if resp.StatusCode == http.StatusOK {
		res.Outcome = OutcomeSent
		return res, nil
	}
	var parsed struct {
		Reason string `json:"reason"`
	}
	_ = json.Unmarshal(body, &parsed)
	res.Reason = parsed.Reason
	switch parsed.Reason {
	case "BadDeviceToken", "Unregistered", "DeviceTokenNotForTopic", "ExpiredToken":
		res.Outcome = OutcomeInvalidToken
	case "ExpiredProviderToken", "TooManyProviderTokenUpdates", "TooManyRequests", "InternalServerError", "ServiceUnavailable", "Shutdown", "IdleTimeout":
		res.Outcome = OutcomeRetry
	default:
		switch {
		case resp.StatusCode == http.StatusGone:
			res.Outcome = OutcomeInvalidToken
		case resp.StatusCode == http.StatusTooManyRequests, resp.StatusCode >= 500:
			res.Outcome = OutcomeRetry
		default:
			res.Outcome = OutcomeFailed
		}
	}
	if resp.StatusCode == http.StatusForbidden && parsed.Reason == "ExpiredProviderToken" {
		c.tokens.mu.Lock()
		c.tokens.token = ""
		c.tokens.mu.Unlock()
	}
	return res, nil
}

// tokenProvider mints ES256 provider tokens and reuses them for up to 50 minutes,
// inside Apple's 20–60 minute window.
type tokenProvider struct {
	keyID  string
	teamID string
	key    *ecdsa.PrivateKey
	now    func() time.Time

	mu       sync.Mutex
	token    string
	issuedAt time.Time
}

const tokenLifetime = 50 * time.Minute

func (p *tokenProvider) Token() (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	if p.token != "" && now.Sub(p.issuedAt) < tokenLifetime {
		return p.token, nil
	}
	header, err := json.Marshal(map[string]string{"alg": "ES256", "kid": p.keyID})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(struct {
		Iss string `json:"iss"`
		Iat int64  `json:"iat"`
	}{p.teamID, now.Unix()})
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, p.key, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign provider token: %w", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	p.token, p.issuedAt = signingInput+"."+base64.RawURLEncoding.EncodeToString(sig), now
	return p.token, nil
}

// ParseJWTSignature is exported for tests: splits a compact JWT signature into r,s.
func ParseJWTSignature(sig []byte) (*big.Int, *big.Int) {
	return new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
}

// LogSender records deliveries to the logger instead of contacting Apple.
type LogSender struct {
	Log *slog.Logger
}

// Send logs the delivery metadata (never the payload or token) and reports success.
func (l *LogSender) Send(ctx context.Context, n Notification) (Result, error) {
	l.Log.InfoContext(ctx, "apns log mode: would send",
		"environment", string(n.Environment),
		"payloadBytes", len(n.Payload),
		"collapseId", n.CollapseID)
	return Result{Outcome: OutcomeSent, StatusCode: http.StatusOK, APNSID: "log-mode"}, nil
}
