// Command apns-relay runs the Arcane push relay.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	kit "go.getarcane.app/kit/pkg"
	"go.getarcane.app/kit/pkg/signals"

	"github.com/getarcaneapp/apns-relay/internal/apns"
	"github.com/getarcaneapp/apns-relay/internal/config"
	"github.com/getarcaneapp/apns-relay/internal/metrics"
	"github.com/getarcaneapp/apns-relay/internal/secrets"
	"github.com/getarcaneapp/apns-relay/internal/server"
	"github.com/getarcaneapp/apns-relay/internal/store"
	"github.com/getarcaneapp/apns-relay/internal/worker"
)

func main() {
	configPath := flag.String("config", os.Getenv("RELAY_CONFIG"), "path to YAML config file (or RELAY_CONFIG)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("apns-relay %s (%s, built %s)\n", config.Version, config.Revision, config.BuildTime)
		return
	}
	if err := run(*configPath); err != nil {
		fmt.Fprintln(os.Stderr, "apns-relay:", err)
		os.Exit(1)
	}
}

func run(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}

	ctx, stop := context.WithCancel(signals.SignalContext(context.Background())) //nolint:forbidigo // process root context
	defer stop()

	opts := &slog.HandlerOptions{Level: cfg.LogLevel}
	log := slog.New(kit.Ternary[slog.Handler](cfg.LogFormat == "text", slog.NewTextHandler(os.Stdout, opts), slog.NewJSONHandler(os.Stdout, opts)))
	slog.SetDefault(log)

	sealer, err := secrets.NewSealer(cfg.EncryptionKey)
	if err != nil {
		return err
	}
	st, err := store.Open(cfg.DatabasePath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer func() { _ = st.Close() }()

	var sender apns.Sender
	switch cfg.APNS.Mode {
	case config.APNSModeLive:
		sender, err = apns.NewClient(apns.Config{
			KeyID:         cfg.APNS.KeyID,
			TeamID:        cfg.APNS.TeamID,
			Topic:         cfg.APNS.Topic,
			PrivateKey:    cfg.APNS.PrivateKey,
			SandboxURL:    cfg.APNS.SandboxURL,
			ProductionURL: cfg.APNS.ProductionURL,
		})
		if err != nil {
			return err
		}
	case config.APNSModeLog:
		log.WarnContext(ctx, "APNs log mode enabled: notifications will NOT be delivered")
		sender = &apns.LogSender{Log: log}
	}

	reg := metrics.New()
	wk := worker.New(worker.Options{
		Store:       st,
		Sender:      sender,
		Sealer:      sealer,
		Metrics:     reg,
		Logger:      log.With("component", "worker"),
		Concurrency: cfg.Workers,
		MaxAttempts: cfg.MaxAttempts,
		Retention:   cfg.Retention,
	})
	srv := server.New(server.Options{
		Config:  cfg,
		Store:   st,
		Sealer:  sealer,
		Metrics: reg,
		Logger:  log.With("component", "http"),
		Wake:    wk.Wake,
	})

	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    16 * 1024,
	}

	errCh := make(chan error, 1)
	go func() {
		log.InfoContext(ctx, "apns-relay listening",
			"addr", cfg.ListenAddr,
			"version", config.Version,
			"apnsMode", string(cfg.APNS.Mode),
			"apnsTopic", cfg.APNS.Topic)
		if serveErr := httpServer.ListenAndServe(); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			errCh <- serveErr
		}
	}()
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		wk.Run(ctx)
	}()
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				srv.SweepLimiters()
			}
		}
	}()

	select {
	case err = <-errCh:
		stop()
		<-workerDone
		return fmt.Errorf("http server: %w", err)
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	if err = httpServer.Shutdown(shutdownCtx); err != nil {
		log.ErrorContext(ctx, "http shutdown", "error", err)
	}
	<-workerDone
	return nil
}
