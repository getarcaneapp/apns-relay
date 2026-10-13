// Package metrics exposes process counters in Prometheus text format without external deps.
package metrics

import (
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// Registry holds all relay metrics.
type Registry struct {
	EventsAccepted      atomic.Int64
	EventsDuplicate     atomic.Int64
	EventsRejected      atomic.Int64
	DeliveriesQueued    atomic.Int64
	DeliveriesSent      atomic.Int64
	DeliveriesRetried   atomic.Int64
	DeliveriesFailed    atomic.Int64
	DeliveriesDropped   atomic.Int64
	InvalidTokenRemoved atomic.Int64
	RateLimitHits       atomic.Int64
	QueueLatencySum     atomic.Int64 // milliseconds
	QueueLatencyCount   atomic.Int64

	mu         sync.Mutex
	apnsStatus map[string]*atomic.Int64
}

// New creates an empty registry.
func New() *Registry {
	return &Registry{apnsStatus: make(map[string]*atomic.Int64)}
}

// ObserveAPNSStatus counts an APNs response by HTTP status and reason.
func (r *Registry) ObserveAPNSStatus(status int, reason string) {
	key := strconv.Itoa(status) + "|" + reason
	r.mu.Lock()
	c, ok := r.apnsStatus[key]
	if !ok {
		c = &atomic.Int64{}
		r.apnsStatus[key] = c
	}
	r.mu.Unlock()
	c.Add(1)
}

// ObserveQueueLatency records how long a delivery waited before its first send attempt.
func (r *Registry) ObserveQueueLatency(ms int64) {
	r.QueueLatencySum.Add(ms)
	r.QueueLatencyCount.Add(1)
}

// WriteTo renders the registry in Prometheus exposition format.
func (r *Registry) WriteTo(w io.Writer) (int64, error) {
	var n int64
	write := func(format string, args ...any) error {
		c, err := fmt.Fprintf(w, format, args...)
		n += int64(c)
		return err
	}
	counters := []struct {
		name string
		help string
		v    *atomic.Int64
	}{
		{"relay_events_accepted_total", "Envelopes accepted for delivery.", &r.EventsAccepted},
		{"relay_events_duplicate_total", "Envelopes ignored as duplicates.", &r.EventsDuplicate},
		{"relay_events_rejected_total", "Envelopes rejected for validation or auth failures.", &r.EventsRejected},
		{"relay_deliveries_queued_total", "Per-recipient deliveries queued.", &r.DeliveriesQueued},
		{"relay_deliveries_sent_total", "Deliveries accepted by APNs.", &r.DeliveriesSent},
		{"relay_deliveries_retried_total", "Delivery attempts scheduled for retry.", &r.DeliveriesRetried},
		{"relay_deliveries_failed_total", "Deliveries permanently failed.", &r.DeliveriesFailed},
		{"relay_deliveries_dropped_total", "Deliveries dropped because the recipient disappeared.", &r.DeliveriesDropped},
		{"relay_invalid_tokens_removed_total", "Installations removed after APNs reported an invalid token.", &r.InvalidTokenRemoved},
		{"relay_rate_limit_hits_total", "Requests rejected by rate limiting.", &r.RateLimitHits},
	}
	for _, c := range counters {
		if err := write("# HELP %s %s\n# TYPE %s counter\n%s %d\n", c.name, c.help, c.name, c.name, c.v.Load()); err != nil {
			return n, err
		}
	}
	if err := write("# HELP relay_queue_latency_milliseconds Time from enqueue to first send attempt.\n# TYPE relay_queue_latency_milliseconds summary\n"+
		"relay_queue_latency_milliseconds_sum %d\nrelay_queue_latency_milliseconds_count %d\n",
		r.QueueLatencySum.Load(), r.QueueLatencyCount.Load()); err != nil {
		return n, err
	}
	r.mu.Lock()
	statuses := maps.Clone(r.apnsStatus)
	r.mu.Unlock()
	if err := write("# HELP relay_apns_responses_total APNs responses by status and reason.\n# TYPE relay_apns_responses_total counter\n"); err != nil {
		return n, err
	}
	for _, k := range slices.Sorted(maps.Keys(statuses)) {
		status, reason, _ := strings.Cut(k, "|")
		if err := write("relay_apns_responses_total{status=%q,reason=%q} %d\n", status, reason, statuses[k].Load()); err != nil {
			return n, err
		}
	}
	return n, nil
}
