// Package worker drains the delivery queue to APNs.
package worker

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/getarcaneapp/apns-relay/internal/apns"
	"github.com/getarcaneapp/apns-relay/internal/metrics"
	"github.com/getarcaneapp/apns-relay/internal/secrets"
	"github.com/getarcaneapp/apns-relay/internal/store"
)

// Options configures the worker.
type Options struct {
	Store        *store.Store
	Sender       apns.Sender
	Sealer       *secrets.Sealer
	Metrics      *metrics.Registry
	Logger       *slog.Logger
	Concurrency  int
	MaxAttempts  int
	Retention    time.Duration
	PollInterval time.Duration
	Lease        time.Duration
	BatchSize    int
	BaseBackoff  time.Duration
	MaxBackoff   time.Duration
	Now          func() time.Time
}

// Worker claims due deliveries and sends them.
type Worker struct {
	o    Options
	wake chan struct{}
}

// New creates a worker with sensible defaults for unset options.
func New(o Options) *Worker {
	o.Concurrency = cmp.Or(o.Concurrency, 8)
	o.MaxAttempts = cmp.Or(o.MaxAttempts, 8)
	o.Retention = cmp.Or(o.Retention, 24*time.Hour)
	o.PollInterval = cmp.Or(o.PollInterval, 2*time.Second)
	o.Lease = cmp.Or(o.Lease, time.Minute)
	o.BatchSize = cmp.Or(o.BatchSize, 64)
	o.BaseBackoff = cmp.Or(o.BaseBackoff, 5*time.Second)
	o.MaxBackoff = cmp.Or(o.MaxBackoff, 15*time.Minute)
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return &Worker{o: o, wake: make(chan struct{}, 1)}
}

// Wake nudges the loop to poll immediately.
func (w *Worker) Wake() {
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

// Run drains the queue until ctx is cancelled.
func (w *Worker) Run(ctx context.Context) {
	ticker := time.NewTicker(w.o.PollInterval)
	defer ticker.Stop()
	prune := time.NewTicker(10 * time.Minute)
	defer prune.Stop()
	for {
		busy, err := w.Drain(ctx)
		if err != nil && ctx.Err() == nil {
			w.o.Logger.ErrorContext(ctx, "drain failed", "error", err)
		}
		if busy {
			// More work may be waiting; loop immediately.
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-w.wake:
		case <-ticker.C:
		case <-prune.C:
			if err = w.o.Store.Prune(ctx, w.o.Retention); err != nil && ctx.Err() == nil {
				w.o.Logger.ErrorContext(ctx, "prune failed", "error", err)
			}
		}
	}
}

// Drain processes one batch. It reports whether a full batch was claimed (so more may remain).
func (w *Worker) Drain(ctx context.Context) (bool, error) {
	batch, err := w.o.Store.ClaimDue(ctx, w.o.BatchSize, w.o.Lease)
	if err != nil {
		return false, err
	}
	if len(batch) == 0 {
		return false, nil
	}
	sem := make(chan struct{}, w.o.Concurrency)
	var wg sync.WaitGroup
	for _, d := range batch {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			return false, ctx.Err()
		}
		wg.Add(1)
		go func(d store.Delivery) {
			defer wg.Done()
			defer func() { <-sem }()
			w.process(ctx, d)
		}(d)
	}
	wg.Wait()
	return len(batch) == w.o.BatchSize, nil
}

func (w *Worker) process(ctx context.Context, d store.Delivery) {
	log := w.o.Logger.With("deliveryId", d.ID, "eventId", d.EventID, "channelId", d.ChannelID)
	if d.Attempts == 0 {
		w.o.Metrics.ObserveQueueLatency(w.o.Now().Sub(d.CreatedAt).Milliseconds())
	}
	if len(d.Payload) == 0 {
		w.terminal(ctx, d, store.DeliveryDropped, "payload missing", log)
		return
	}
	in, err := w.o.Store.GetInstallation(ctx, d.InstallationID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			w.terminal(ctx, d, store.DeliveryDropped, "installation removed", log)
			return
		}
		w.retry(ctx, d, "load installation: "+err.Error(), log)
		return
	}
	token, err := w.o.Sealer.Open(in.DeviceTokenEnc, []byte(in.ID))
	if err != nil {
		w.terminal(ctx, d, store.DeliveryFailed, "cannot decrypt device token", log)
		return
	}
	sendCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	res, err := w.o.Sender.Send(sendCtx, apns.Notification{
		DeviceToken: string(token),
		Environment: apns.Environment(in.APNSEnvironment),
		Payload:     d.Payload,
		CollapseID:  d.CollapseID,
		Expiration:  w.o.Now().Add(24 * time.Hour),
	})
	if err != nil {
		w.retry(ctx, d, "transport: "+err.Error(), log)
		return
	}
	w.o.Metrics.ObserveAPNSStatus(res.StatusCode, res.Reason)
	apnsReason := fmt.Sprintf("apns %d %s", res.StatusCode, res.Reason)
	switch res.Outcome {
	case apns.OutcomeSent:
		if err = w.o.Store.MarkSent(ctx, d.ID); err != nil {
			log.ErrorContext(ctx, "mark sent failed", "error", err)
			return
		}
		w.o.Metrics.DeliveriesSent.Add(1)
		log.InfoContext(ctx, "delivered", "apnsId", res.APNSID, "environment", in.APNSEnvironment)
	case apns.OutcomeRetry:
		w.retry(ctx, d, apnsReason, log)
	case apns.OutcomeInvalidToken:
		if err = w.o.Store.DeleteInstallation(ctx, in.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
			log.ErrorContext(ctx, "remove installation failed", "error", err)
		} else {
			w.o.Metrics.InvalidTokenRemoved.Add(1)
		}
		w.terminal(ctx, d, store.DeliveryDropped, apnsReason, log)
		log.InfoContext(ctx, "installation removed after invalid token", "installationId", in.ID, "reason", res.Reason)
	case apns.OutcomeFailed:
		w.terminal(ctx, d, store.DeliveryFailed, apnsReason, log)
	}
}

func (w *Worker) retry(ctx context.Context, d store.Delivery, reason string, log *slog.Logger) {
	attempt := d.Attempts + 1
	if attempt >= w.o.MaxAttempts {
		w.terminal(ctx, d, store.DeliveryFailed, "max attempts: "+reason, log)
		return
	}
	// Exponential backoff with full jitter, capped at MaxBackoff.
	exp := min(float64(w.o.BaseBackoff)*math.Pow(2, float64(attempt-1)), float64(w.o.MaxBackoff))
	next := w.o.Now().Add(time.Duration(exp/2 + rand.Float64()*exp/2)) //nolint:gosec // jitter, not security-sensitive
	if err := w.o.Store.MarkRetry(ctx, d.ID, next, reason); err != nil {
		log.ErrorContext(ctx, "mark retry failed", "error", err)
		return
	}
	w.o.Metrics.DeliveriesRetried.Add(1)
	log.WarnContext(ctx, "delivery retry scheduled", "attempt", attempt, "nextAttemptAt", next, "reason", reason)
}

func (w *Worker) terminal(ctx context.Context, d store.Delivery, status, reason string, log *slog.Logger) {
	if err := w.o.Store.MarkTerminal(ctx, d.ID, status, reason); err != nil {
		log.ErrorContext(ctx, "mark terminal failed", "error", err)
		return
	}
	switch status {
	case store.DeliveryFailed:
		w.o.Metrics.DeliveriesFailed.Add(1)
		log.ErrorContext(ctx, "delivery failed", "reason", reason)
	default:
		w.o.Metrics.DeliveriesDropped.Add(1)
		log.InfoContext(ctx, "delivery dropped", "reason", reason)
	}
}
