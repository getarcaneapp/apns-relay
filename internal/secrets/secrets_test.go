package secrets

import (
	"bytes"
	"strings"
	"testing"
)

func TestSealRoundTrip(t *testing.T) {
	s, err := NewSealer(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := s.Seal([]byte("token"), []byte("ins_1"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Open(sealed, []byte("ins_1"))
	if err != nil || string(got) != "token" {
		t.Fatalf("open: %v %q", err, got)
	}
	if _, err = s.Open(sealed, []byte("ins_2")); err == nil {
		t.Fatal("expected AAD mismatch to fail")
	}
}

func TestIDsAndSecrets(t *testing.T) {
	id := NewID("ch_")
	if !strings.HasPrefix(id, "ch_") || len(id) != 35 {
		t.Fatalf("unexpected id %q", id)
	}
	sec := NewSecret()
	if !SecretMatches(sec, HashSecret(sec)) || SecretMatches("nope", HashSecret(sec)) {
		t.Fatal("secret hashing mismatch")
	}
}
