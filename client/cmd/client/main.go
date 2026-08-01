package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ricardo/frp-panel-platform/client/internal/app"
	"github.com/ricardo/frp-panel-platform/client/internal/config"
	"github.com/ricardo/frp-panel-platform/client/internal/httpapi"
)

func main() {
	cfg := config.Load()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := cfg.EnsureDirs(); err != nil {
		logger.Error("config", "error", err)
		os.Exit(1)
	}
	if err := cfg.ValidateListenSecurity(); err != nil {
		logger.Error("client_listener_security", "error", err)
		os.Exit(1)
	}
	client := app.New(cfg)
	recoveryCtx, recoveryCancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := client.Supervisor.RecoverOrphan(recoveryCtx); err != nil {
		logger.Error("frpc_orphan_recovery", "error", err)
	}
	recoveryCancel()
	server := &http.Server{Addr: cfg.ListenAddr, Handler: httpapi.New(client).Handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	go func() {
		logger.Info("client_started", "addr", cfg.ListenAddr, "frpc_mode", map[bool]string{true: "fixed-binary", false: "development-simulation"}[cfg.FRPCBinary != ""])
		var err error
		if cfg.TLSCertFile != "" {
			err = server.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		} else {
			err = server.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("client_stopped", "error", err)
			os.Exit(1)
		}
	}()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	<-signals
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = client.Logout(ctx)
	_ = server.Shutdown(ctx)
}
