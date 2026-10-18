// Package fcm sends data messages to Android devices through the Firebase Cloud
// Messaging HTTP v1 API, authenticating with a service-account OAuth2 token.
package fcm

import (
	"bytes"
	"cmp"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/getarcaneapp/apns-relay/internal/push"
)

// messagingScope is the OAuth2 scope required by the FCM HTTP v1 API.
const messagingScope = "https://www.googleapis.com/auth/firebase.messaging"

// invalidTokenMessage is how FCM describes a malformed registration token. It
// arrives as a bare INVALID_ARGUMENT with no field details, so the message is the
// only way to tell it apart from a payload error.
const invalidTokenMessage = "The registration token is not a valid FCM registration token"

// Config for the live client.
type Config struct {
	ProjectID   string
	ClientEmail string
	PrivateKey  *rsa.PrivateKey
	// TokenURL is where access tokens are fetched. TokenAudience is the aud claim
	// Google checks (the service account's token_uri); it defaults to TokenURL.
	TokenURL      string
	TokenAudience string
	BaseURL       string
}

// Client sends to FCM using a persistent HTTP/2 connection pool.
type Client struct {
	cfg    Config
	http   *http.Client
	tokens *tokenProvider
	now    func() time.Time
}

// NewClient constructs a live client.
func NewClient(cfg Config) (*Client, error) {
	if cfg.PrivateKey == nil || cfg.ClientEmail == "" || cfg.ProjectID == "" {
		return nil, errors.New("fcm: service account key, client email and project id are required")
	}
	if cfg.TokenURL == "" || cfg.BaseURL == "" {
		return nil, errors.New("fcm: token and base URLs are required")
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
	httpClient := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	return &Client{
		cfg:  cfg,
		http: httpClient,
		tokens: &tokenProvider{
			email:    cfg.ClientEmail,
			key:      cfg.PrivateKey,
			tokenURL: cfg.TokenURL,
			audience: cmp.Or(cfg.TokenAudience, cfg.TokenURL),
			http:     httpClient,
			now:      time.Now,
		},
		now: time.Now,
	}, nil
}

// storedPayload is what envelope.BuildFCMPayload produces and the queue stores.
type storedPayload struct {
	Data json.RawMessage `json:"data"`
}

// androidConfig sets no collapse_key: FCM keeps only four collapsible messages
// per offline device and every alert has its own dedupe key. Repeats replace
// each other on the device through the payload's tag.
type androidConfig struct {
	Priority string `json:"priority"`
	TTL      string `json:"ttl,omitempty"`
}

type message struct {
	Token   string          `json:"token"`
	Data    json.RawMessage `json:"data"`
	Android androidConfig   `json:"android"`
}

// Send delivers one data message. Android delivery options live here, like the
// apns-* headers in the APNs client, so the stored payload only carries data.
func (c *Client) Send(ctx context.Context, n push.Notification) (push.Result, error) {
	var stored storedPayload
	if err := json.Unmarshal(n.Payload, &stored); err != nil || len(stored.Data) == 0 {
		return push.Result{Outcome: push.OutcomeFailed, Reason: "invalid payload"}, nil
	}
	msg := message{
		Token:   n.DeviceToken,
		Data:    stored.Data,
		Android: androidConfig{Priority: "HIGH"},
	}
	if !n.Expiration.IsZero() {
		ttl := max(n.Expiration.Sub(c.now()).Round(time.Second), 0)
		msg.Android.TTL = strconv.FormatInt(int64(ttl.Seconds()), 10) + "s"
	}
	body, err := json.Marshal(map[string]message{"message": msg})
	if err != nil {
		return push.Result{Outcome: push.OutcomeFailed, Reason: "invalid payload"}, nil
	}
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return push.Result{Outcome: push.OutcomeRetry}, err
	}
	endpoint := c.cfg.BaseURL + "/v1/projects/" + url.PathEscape(c.cfg.ProjectID) + "/messages:send"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return push.Result{Outcome: push.OutcomeFailed}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return push.Result{Outcome: push.OutcomeRetry, Reason: "transport"}, err
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	var parsed struct {
		Name  string `json:"name"`
		Error struct {
			Status  string `json:"status"`
			Message string `json:"message"`
			Details []struct {
				Type            string `json:"@type"`
				ErrorCode       string `json:"errorCode"`
				FieldViolations []struct {
					Field string `json:"field"`
				} `json:"fieldViolations"`
			} `json:"details"`
		} `json:"error"`
	}
	_ = json.Unmarshal(respBody, &parsed)
	res := push.Result{StatusCode: resp.StatusCode, ID: parsed.Name}
	if resp.StatusCode == http.StatusOK {
		res.Outcome = push.OutcomeSent
		return res, nil
	}
	// Prefer the FCM-specific error code; fall back to the canonical gRPC status.
	res.Reason = parsed.Error.Status
	tokenViolation := parsed.Error.Message == invalidTokenMessage
	for _, d := range parsed.Error.Details {
		if strings.HasSuffix(d.Type, "google.firebase.fcm.v1.FcmError") && d.ErrorCode != "" {
			res.Reason = d.ErrorCode
		}
		for _, v := range d.FieldViolations {
			if v.Field == "message.token" {
				tokenViolation = true
			}
		}
	}
	switch res.Reason {
	case "UNREGISTERED":
		res.Outcome = push.OutcomeInvalidToken
	case "INVALID_ARGUMENT":
		// Only a malformed token removes the installation; anything else is a
		// payload bug and must not wipe out every Android device.
		if tokenViolation {
			res.Outcome = push.OutcomeInvalidToken
		} else {
			res.Outcome = push.OutcomeFailed
		}
	case "QUOTA_EXCEEDED", "UNAVAILABLE", "INTERNAL":
		res.Outcome = push.OutcomeRetry
	default:
		// SENDER_ID_MISMATCH lands here as Failed, not InvalidToken: it means the
		// service account is for a different Firebase project than the app, and
		// treating it as a dead token would delete every Android installation.
		switch {
		case resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusTooManyRequests, resp.StatusCode >= 500:
			res.Outcome = push.OutcomeRetry
		default:
			res.Outcome = push.OutcomeFailed
		}
	}
	if resp.StatusCode == http.StatusUnauthorized {
		c.tokens.reset()
	}
	return res, nil
}

// tokenProvider exchanges a signed service-account assertion for an OAuth2 access
// token and reuses it until shortly before it expires.
type tokenProvider struct {
	email    string
	key      *rsa.PrivateKey
	tokenURL string
	audience string
	http     *http.Client
	now      func() time.Time

	// fetchMu lets one caller exchange a token at a time while the others wait for
	// its result; mu only guards the cached value, so reset never waits on Google.
	fetchMu   sync.Mutex
	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

const (
	// tokenRefreshMargin renews the access token this long before Google expires it.
	tokenRefreshMargin = 5 * time.Minute
	// clockSkew backdates iat so a relay clock running slightly fast isn't rejected.
	clockSkew = 10 * time.Second
	// maxErrorBody caps how much of a token endpoint error reaches logs and last_error.
	maxErrorBody = 256
)

func (p *tokenProvider) cached(now time.Time) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.token != "" && now.Before(p.expiresAt) {
		return p.token
	}
	return ""
}

func (p *tokenProvider) Token(ctx context.Context) (string, error) {
	if token := p.cached(p.now()); token != "" {
		return token, nil
	}
	p.fetchMu.Lock()
	defer p.fetchMu.Unlock()
	// Another caller may have fetched a token while this one waited.
	now := p.now()
	if token := p.cached(now); token != "" {
		return token, nil
	}
	assertion, err := p.assertion(now)
	if err != nil {
		return "", err
	}
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {assertion},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := p.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch access token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	if resp.StatusCode != http.StatusOK {
		if len(body) > maxErrorBody {
			body = body[:maxErrorBody]
		}
		return "", fmt.Errorf("fetch access token: status %d: %s", resp.StatusCode, strings.ToValidUTF8(strings.TrimSpace(string(body)), ""))
	}
	var parsed struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err = json.Unmarshal(body, &parsed); err != nil || parsed.AccessToken == "" {
		return "", errors.New("fetch access token: malformed response")
	}
	p.mu.Lock()
	p.token = parsed.AccessToken
	p.expiresAt = now.Add(time.Duration(parsed.ExpiresIn)*time.Second - tokenRefreshMargin)
	p.mu.Unlock()
	return parsed.AccessToken, nil
}

// assertion mints the RS256 JWT Google's token endpoint expects from a service account.
func (p *tokenProvider) assertion(now time.Time) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(struct {
		Iss   string `json:"iss"`
		Scope string `json:"scope"`
		Aud   string `json:"aud"`
		Iat   int64  `json:"iat"`
		Exp   int64  `json:"exp"`
	}{p.email, messagingScope, p.audience, now.Add(-clockSkew).Unix(), now.Add(-clockSkew + time.Hour).Unix()})
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign service account assertion: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (p *tokenProvider) reset() {
	p.mu.Lock()
	p.token = ""
	p.mu.Unlock()
}

// LogSender records deliveries to the logger instead of contacting Google.
type LogSender struct {
	Log *slog.Logger
}

// Send logs the delivery metadata (never the payload or token) and reports success.
func (l *LogSender) Send(ctx context.Context, n push.Notification) (push.Result, error) {
	l.Log.InfoContext(ctx, "fcm log mode: would send",
		"payloadBytes", len(n.Payload),
		"collapseId", n.CollapseID)
	return push.Result{Outcome: push.OutcomeSent, StatusCode: http.StatusOK, ID: "log-mode"}, nil
}
