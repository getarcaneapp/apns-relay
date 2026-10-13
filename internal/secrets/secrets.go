// Package secrets provides identifiers, secret hashing and at-rest encryption helpers.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
)

// NewID returns a random, URL-safe identifier with the given prefix (e.g. "ch_").
func NewID(prefix string) string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return prefix + hex.EncodeToString(b[:])
}

// NewSecret returns a random 32-byte secret encoded as base64url (no padding).
func NewSecret() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// HashSecret returns the SHA-256 digest of a secret for storage.
// Secrets are high-entropy random values, so a plain hash is sufficient.
func HashSecret(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

// SecretMatches compares a presented secret against a stored hash in constant time.
func SecretMatches(secret string, hash []byte) bool {
	return subtle.ConstantTimeCompare(HashSecret(secret), hash) == 1
}

// Sealer encrypts and decrypts small values with AES-256-GCM.
type Sealer struct {
	aead cipher.AEAD
}

// NewSealer builds a Sealer from a 32-byte key.
func NewSealer(key []byte) (*Sealer, error) {
	if len(key) != 32 {
		return nil, errors.New("sealer key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Sealer{aead: aead}, nil
}

// Seal encrypts plaintext, binding it to the additional data (e.g. the owning row id).
func (s *Sealer) Seal(plaintext, additional []byte) ([]byte, error) {
	ns := s.aead.NonceSize()
	out := make([]byte, ns, ns+len(plaintext)+s.aead.Overhead())
	if _, err := io.ReadFull(rand.Reader, out[:ns]); err != nil {
		return nil, err
	}
	return s.aead.Seal(out, out[:ns], plaintext, additional), nil
}

// Open decrypts a value produced by Seal with the same additional data.
func (s *Sealer) Open(sealed, additional []byte) ([]byte, error) {
	ns := s.aead.NonceSize()
	if len(sealed) < ns {
		return nil, errors.New("sealed value too short")
	}
	return s.aead.Open(nil, sealed[:ns], sealed[ns:], additional)
}
