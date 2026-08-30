// Package signing verifies signed manager requests and pairing tokens.
//
// Two channel key algorithms are supported: Ed25519 and ML-DSA-87 (FIPS 204).
// Apple's APNs itself only accepts ES256 provider tokens, which is handled by
// package apns; the algorithms here only cover the manager <-> relay contract.
package signing

import (
	"crypto/ed25519"
	"crypto/mldsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// SignatureHeader carries the base64 signature over the raw request body.
const SignatureHeader = "X-Arcane-Signature"

// PairingTokenPrefix identifies v1 pairing tokens.
const PairingTokenPrefix = "arcane-pair-v1" //nolint:gosec // format tag, not a credential

// MaxPairingTokenLifetime bounds exp-iat so a manager cannot mint long-lived tokens.
const MaxPairingTokenLifetime = 10 * time.Minute

// Algorithm names a channel signature scheme.
type Algorithm string

// Supported channel algorithms.
const (
	AlgEd25519 Algorithm = "ed25519"
	AlgMLDSA87 Algorithm = "ml-dsa-87"
)

// DefaultAlgorithm is used when a registration omits the algorithm.
const DefaultAlgorithm = AlgEd25519

// Errors returned by verification helpers.
var (
	ErrBadSignature = errors.New("invalid signature")
	ErrBadToken     = errors.New("malformed pairing token")
	ErrTokenExpired = errors.New("pairing token expired")
	ErrBadAlgorithm = errors.New("unsupported algorithm")
)

// PublicKey is an algorithm-tagged verification key.
type PublicKey struct {
	Algorithm Algorithm
	ed        ed25519.PublicKey
	ml        *mldsa.PublicKey
}

// ParseAlgorithm validates an algorithm name ("" means DefaultAlgorithm).
func ParseAlgorithm(s string) (Algorithm, error) {
	switch Algorithm(strings.ToLower(strings.TrimSpace(s))) {
	case "":
		return DefaultAlgorithm, nil
	case AlgEd25519:
		return AlgEd25519, nil
	case AlgMLDSA87:
		return AlgMLDSA87, nil
	default:
		return "", fmt.Errorf("%w: %q", ErrBadAlgorithm, s)
	}
}

// NewPublicKey builds a key from its raw encoding.
func NewPublicKey(alg Algorithm, raw []byte) (*PublicKey, error) {
	switch alg {
	case AlgEd25519:
		if len(raw) != ed25519.PublicKeySize {
			return nil, errors.New("ed25519 public key must be 32 bytes")
		}
		return &PublicKey{Algorithm: alg, ed: ed25519.PublicKey(raw)}, nil
	case AlgMLDSA87:
		pk, err := mldsa.NewPublicKey(mldsa.MLDSA87(), raw)
		if err != nil {
			return nil, fmt.Errorf("ml-dsa-87 public key: %w", err)
		}
		return &PublicKey{Algorithm: alg, ml: pk}, nil
	default:
		return nil, fmt.Errorf("%w: %q", ErrBadAlgorithm, alg)
	}
}

// DecodePublicKey parses a base64 (std/url, padded or raw) public key for alg.
func DecodePublicKey(alg Algorithm, encoded string) (*PublicKey, error) {
	raw, err := decodeBase64(encoded)
	if err != nil {
		return nil, errors.New("public key must be base64")
	}
	return NewPublicKey(alg, raw)
}

// Bytes returns the raw key encoding for storage.
func (k *PublicKey) Bytes() []byte {
	if k.ml != nil {
		return k.ml.Bytes()
	}
	return []byte(k.ed)
}

// Verify checks sig over msg.
func (k *PublicKey) Verify(msg, sig []byte) error {
	switch k.Algorithm {
	case AlgEd25519:
		if len(sig) != ed25519.SignatureSize || !ed25519.Verify(k.ed, msg, sig) {
			return ErrBadSignature
		}
		return nil
	case AlgMLDSA87:
		if err := mldsa.Verify(k.ml, msg, sig, nil); err != nil {
			return ErrBadSignature
		}
		return nil
	default:
		return ErrBadAlgorithm
	}
}

// DecodeSignature parses a base64 signature from a header value.
func DecodeSignature(raw string) ([]byte, error) {
	b, err := decodeBase64(raw)
	if err != nil || len(b) == 0 {
		return nil, errors.New("signature must be base64")
	}
	return b, nil
}

func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	var firstErr error
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		b, err := enc.DecodeString(s)
		if err == nil {
			return b, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return nil, firstErr
}

// PairingClaims is the payload of a pairing token minted by the manager.
type PairingClaims struct {
	ChannelID string `json:"channelId"`
	Subject   string `json:"sub"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	Nonce     string `json:"nonce"`
}

// SplitPairingToken parses the token structure without verifying it, returning the
// unverified claims, the signed payload bytes and the signature.
//
// Token format: "arcane-pair-v1.<base64url(payload JSON)>.<base64url(signature)>".
func SplitPairingToken(token string) (PairingClaims, []byte, []byte, error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 || parts[0] != PairingTokenPrefix {
		return PairingClaims{}, nil, nil, ErrBadToken
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return PairingClaims{}, nil, nil, ErrBadToken
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) == 0 {
		return PairingClaims{}, nil, nil, ErrBadToken
	}
	var claims PairingClaims
	dec := json.NewDecoder(strings.NewReader(string(payload)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&claims); err != nil {
		return PairingClaims{}, nil, nil, fmt.Errorf("%w: %w", ErrBadToken, err)
	}
	if claims.ChannelID == "" || claims.Subject == "" || claims.Nonce == "" || claims.ExpiresAt == 0 {
		return PairingClaims{}, nil, nil, fmt.Errorf("%w: missing fields", ErrBadToken)
	}
	return claims, payload, sig, nil
}

// VerifyPairingToken verifies the signature and time bounds of a parsed token.
func VerifyPairingToken(pub *PublicKey, claims PairingClaims, payload, sig []byte, now time.Time) error {
	if err := pub.Verify(payload, sig); err != nil {
		return err
	}
	exp := time.Unix(claims.ExpiresAt, 0)
	if !now.Before(exp) {
		return ErrTokenExpired
	}
	iat := time.Unix(claims.IssuedAt, 0)
	if claims.IssuedAt == 0 || exp.Sub(iat) > MaxPairingTokenLifetime || iat.After(now.Add(time.Minute)) {
		return fmt.Errorf("%w: invalid time bounds", ErrBadToken)
	}
	return nil
}

// Signer produces signatures; used by tests and as the reference for the manager side.
type Signer interface {
	Sign(msg []byte) ([]byte, error)
}

// Ed25519Signer signs with an Ed25519 private key.
type Ed25519Signer struct{ Key ed25519.PrivateKey }

// Sign implements Signer.
func (s Ed25519Signer) Sign(msg []byte) ([]byte, error) { return ed25519.Sign(s.Key, msg), nil }

// MLDSASigner signs with an ML-DSA-87 private key.
type MLDSASigner struct{ Key *mldsa.PrivateKey }

// Sign implements Signer.
func (s MLDSASigner) Sign(msg []byte) ([]byte, error) { return s.Key.Sign(nil, msg, nil) }

// MintPairingToken produces a token for the given claims.
func MintPairingToken(signer Signer, claims PairingClaims) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	sig, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return PairingTokenPrefix + "." + base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
