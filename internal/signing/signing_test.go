package signing

import (
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

type keypair struct {
	alg    Algorithm
	pub    *PublicKey
	signer Signer
}

func keypairs(t *testing.T) []keypair {
	t.Helper()
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	ed, err := NewPublicKey(AlgEd25519, edPub)
	if err != nil {
		t.Fatal(err)
	}
	mlPriv, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		t.Fatal(err)
	}
	ml, err := NewPublicKey(AlgMLDSA87, mlPriv.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return []keypair{
		{AlgEd25519, ed, Ed25519Signer{edPriv}},
		{AlgMLDSA87, ml, MLDSASigner{mlPriv}},
	}
}

func TestPairingTokenRoundTrip(t *testing.T) {
	for _, kp := range keypairs(t) {
		t.Run(string(kp.alg), func(t *testing.T) {
			now := time.Now()
			claims := PairingClaims{ChannelID: "ch_1", Subject: "u1", IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(), Nonce: "n1"}
			tok, err := MintPairingToken(kp.signer, claims)
			if err != nil {
				t.Fatal(err)
			}
			got, payload, sig, err := SplitPairingToken(tok)
			if err != nil {
				t.Fatal(err)
			}
			if got != claims {
				t.Fatalf("claims mismatch: %+v", got)
			}
			if err := VerifyPairingToken(kp.pub, got, payload, sig, now); err != nil {
				t.Fatal(err)
			}
			if err := VerifyPairingToken(kp.pub, got, payload, sig, now.Add(6*time.Minute)); !errors.Is(err, ErrTokenExpired) {
				t.Fatalf("expected expired, got %v", err)
			}
			// Tamper with the payload byte.
			payload[0] ^= 1
			if err := VerifyPairingToken(kp.pub, got, payload, sig, now); !errors.Is(err, ErrBadSignature) {
				t.Fatalf("expected bad signature, got %v", err)
			}
		})
	}
}

func TestSignatureCrossAlgorithmRejected(t *testing.T) {
	kps := keypairs(t)
	msg := []byte("body")
	sig, _ := kps[0].signer.Sign(msg)
	if err := kps[1].pub.Verify(msg, sig); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("ml-dsa key must reject ed25519 signature, got %v", err)
	}
	sig, _ = kps[1].signer.Sign(msg)
	if err := kps[0].pub.Verify(msg, sig); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("ed25519 key must reject ml-dsa signature, got %v", err)
	}
}

func TestPairingTokenRejectsLongLifetime(t *testing.T) {
	kp := keypairs(t)[0]
	now := time.Now()
	tok, _ := MintPairingToken(kp.signer, PairingClaims{ChannelID: "ch_1", Subject: "u1", IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(), Nonce: "n1"})
	claims, payload, sig, err := SplitPairingToken(tok)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPairingToken(kp.pub, claims, payload, sig, now); !errors.Is(err, ErrBadToken) {
		t.Fatalf("expected bad token, got %v", err)
	}
}

func TestSplitPairingTokenMalformed(t *testing.T) {
	for _, tok := range []string{"", "a.b.c", "arcane-pair-v1.!!.x", "arcane-pair-v1.e30.AAAA"} {
		if _, _, _, err := SplitPairingToken(tok); !errors.Is(err, ErrBadToken) {
			t.Errorf("%q: expected ErrBadToken, got %v", tok, err)
		}
	}
}

func TestParseAlgorithm(t *testing.T) {
	if a, err := ParseAlgorithm(""); err != nil || a != AlgEd25519 {
		t.Fatalf("default: %v %v", a, err)
	}
	if a, err := ParseAlgorithm("ML-DSA-87"); err != nil || a != AlgMLDSA87 {
		t.Fatalf("ml-dsa: %v %v", a, err)
	}
	if _, err := ParseAlgorithm("rsa"); !errors.Is(err, ErrBadAlgorithm) {
		t.Fatalf("expected bad algorithm, got %v", err)
	}
}
