// Package ratelimit implements a small in-memory token bucket keyed by string.
package ratelimit

import (
	"sync"
	"time"
)

type bucket struct {
	tokens   float64
	lastSeen time.Time
}

// Limiter allows `limit` events per `window` for each key, refilling continuously.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	limit   float64
	window  time.Duration
	now     func() time.Time
}

// New creates a limiter. A limit <= 0 disables limiting.
func New(limit int, window time.Duration) *Limiter {
	return &Limiter{buckets: make(map[string]*bucket), limit: float64(limit), window: window, now: time.Now}
}

// Allow reports whether one event for key is permitted now.
func (l *Limiter) Allow(key string) bool {
	if l.limit <= 0 {
		return true
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.limit, lastSeen: now}
		l.buckets[key] = b
	}
	elapsed := now.Sub(b.lastSeen)
	b.lastSeen = now
	b.tokens = min(b.tokens+elapsed.Seconds()*(l.limit/l.window.Seconds()), l.limit)
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Sweep drops idle buckets; call periodically.
func (l *Limiter) Sweep() {
	cutoff := l.now().Add(-2 * l.window)
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, b := range l.buckets {
		if b.lastSeen.Before(cutoff) {
			delete(l.buckets, k)
		}
	}
}
