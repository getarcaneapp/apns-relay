package ratelimit

import (
	"testing"
	"time"
)

func TestLimiter(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	l := New(3, time.Minute)
	l.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if !l.Allow("a") {
			t.Fatalf("call %d should be allowed", i)
		}
	}
	if l.Allow("a") {
		t.Fatal("4th call should be limited")
	}
	if !l.Allow("b") {
		t.Fatal("other key should be independent")
	}
	now = now.Add(20 * time.Second)
	if !l.Allow("a") {
		t.Fatal("should refill one token after 20s")
	}
	now = now.Add(3 * time.Minute)
	l.Sweep()
	if len(l.buckets) != 0 {
		t.Fatalf("expected sweep to clear buckets, have %d", len(l.buckets))
	}
}
