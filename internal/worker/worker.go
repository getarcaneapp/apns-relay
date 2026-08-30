// Package worker drains the delivery queue to APNs.
package worker

import (
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
	if o.Concurrency <= 0 {
		o.Concurrency = 8
	}
	if o.MaxAttempts <= 0 {
		o.MaxAttempts = 8
	}
	if o.Retention <= 0 {
		o.Retention = 24 * time.Hour
	}
	if o.PollInterval <= 0 {
		o.PollInterval = 2 * time.Second
	}
	if o.Lease <= 0 {
		o.Lease = time.Minute
	}
	if o.BatchSize <= 0 {
		o.BatchSize = 64
	}
	if o.BaseBackoff <= 0 {
		o.BaseBackoff = 5 * time.Second
	}
	if o.MaxBackoff <= 0 {
		o.MaxBackoff = 15 * time.Minute
	}
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
			w.o.Logger.Error("drain failed", slog.String("error", err.Error()))
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
			if err := w.o.Store.Prune(ctx, w.o.Retention); err != nil && ctx.Err() == nil {
				w.o.Logger.Error("prune failed", slog.String("error", err.Error()))
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
	log := w.o.Logger.With(slog.Int64("deliveryId", d.ID), slog.String("eventId", d.EventID), slog.String("channelId", d.ChannelID))
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
	switch res.Outcome {
	case apns.OutcomeSent:
		if err := w.o.Store.MarkSent(ctx, d.ID); err != nil {
			log.Error("mark sent failed", slog.String("error", err.Error()))
			return
		}
		w.o.Metrics.DeliveriesSent.Add(1)
		log.Info("delivered", slog.String("apnsId", res.APNSID), slog.String("environment", in.APNSEnvironment))
	case apns.OutcomeRetry:
		w.retry(ctx, d, fmt.Sprintf("apns %d %s", res.StatusCode, res.Reason), log)
	case apns.OutcomeInvalidToken:
		if err := w.o.Store.DeleteInstallation(ctx, in.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
			log.Error("remove installation failed", slog.String("error", err.Error()))
		} else {
			w.o.Metrics.InvalidTokenRemoved.Add(1)
		}
		w.terminal(ctx, d, store.DeliveryDropped, fmt.Sprintf("apns %d %s", res.StatusCode, res.Reason), log)
		log.Info("installation removed after invalid token", slog.String("installationId", in.ID), slog.String("reason", res.Reason))
	case apns.OutcomeFailed:
		w.terminal(ctx, d, store.DeliveryFailed, fmt.Sprintf("apns %d %s", res.StatusCode, res.Reason), log)
	}
}

func (w *Worker) retry(ctx context.Context, d store.Delivery, reason string, log *slog.Logger) {
	attempt := d.Attempts + 1
	if attempt >= w.o.MaxAttempts {
		w.terminal(ctx, d, store.DeliveryFailed, "max attempts: "+reason, log)
		return
	}
	next := w.o.Now().Add(w.backoff(attempt))
	if err := w.o.Store.MarkRetry(ctx, d.ID, next, reason); err != nil {
		log.Error("mark retry failed", slog.String("error", err.Error()))
		return
	}
	w.o.Metrics.DeliveriesRetried.Add(1)
	log.Warn("delivery retry scheduled", slog.Int("attempt", attempt), slog.Time("nextAttemptAt", next), slog.String("reason", reason))
}

func (w *Worker) terminal(ctx context.Context, d store.Delivery, status, reason string, log *slog.Logger) {
	if err := w.o.Store.MarkTerminal(ctx, d.ID, status, reason); err != nil {
		log.Error("mark terminal failed", slog.String("error", err.Error()))
		return
	}
	switch status {
	case store.DeliveryFailed:
		w.o.Metrics.DeliveriesFailed.Add(1)
		log.Error("delivery failed", slog.String("reason", reason))
	default:
		w.o.Metrics.DeliveriesDropped.Add(1)
		log.Info("delivery dropped", slog.String("reason", reason))
	}
}

// backoff grows exponentially with full jitter, capped at MaxBackoff.
func (w *Worker) backoff(attempt int) time.Duration {
	exp := float64(w.o.BaseBackoff) * math.Pow(2, float64(attempt-1))
	if exp > float64(w.o.MaxBackoff) {
		exp = float64(w.o.MaxBackoff)
	}
	return time.Duration(exp/2 + rand.Float64()*exp/2) //nolint:gosec // jitter, not security-sensitive
}
