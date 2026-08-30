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
	"os/signal"
	"syscall"
	"time"

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

	var handler slog.Handler
	opts := &slog.HandlerOptions{Level: cfg.LogLevel}
	if cfg.LogFormat == "text" {
		handler = slog.NewTextHandler(os.Stdout, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}
	log := slog.New(handler)
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
		client, err := apns.NewClient(apns.Config{
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
		sender = client
	case config.APNSModeLog:
		log.Warn("APNs log mode enabled: notifications will NOT be delivered")
		sender = &apns.LogSender{Log: log}
	}

	reg := metrics.New()
	wk := worker.New(worker.Options{
		Store:       st,
		Sender:      sender,
		Sealer:      sealer,
		Metrics:     reg,
		Logger:      log.With(slog.String("component", "worker")),
		Concurrency: cfg.Workers,
		MaxAttempts: cfg.MaxAttempts,
		Retention:   cfg.Retention,
	})
	srv := server.New(server.Options{
		Config:  cfg,
		Store:   st,
		Sealer:  sealer,
		Metrics: reg,
		Logger:  log.With(slog.String("component", "http")),
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

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		log.Info("apns-relay listening",
			slog.String("addr", cfg.ListenAddr),
			slog.String("version", config.Version),
			slog.String("apnsMode", string(cfg.APNS.Mode)),
			slog.String("apnsTopic", cfg.APNS.Topic))
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
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
	case err := <-errCh:
		stop()
		<-workerDone
		return fmt.Errorf("http server: %w", err)
	case <-ctx.Done():
	}
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Error("http shutdown", slog.String("error", err.Error()))
	}
	<-workerDone
	return nil
}
