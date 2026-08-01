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

	"github.com/ricardo/frp-panel-platform/server/internal/config"
	"github.com/ricardo/frp-panel-platform/server/internal/crypto"
	"github.com/ricardo/frp-panel-platform/server/internal/db"
	"github.com/ricardo/frp-panel-platform/server/internal/httpapi"
	"github.com/ricardo/frp-panel-platform/server/internal/service"
)

func main() {
	cfg := config.Load()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := cfg.EnsureDirs(); err != nil {
		logger.Error("config", "error", err)
		os.Exit(1)
	}
	secrets, err := crypto.Load(cfg.DataDir, cfg.MasterKeyPath, cfg.ConfigSigningPath)
	if err != nil {
		logger.Error("secrets", "error", err)
		os.Exit(1)
	}
	database, err := db.Open(cfg.DBPath)
	if err != nil {
		logger.Error("database", "error", err)
		os.Exit(1)
	}
	defer database.Close()
	app := service.New(database, cfg, secrets)
	initialPassword, err := app.EnsureAdmin(context.Background())
	if err != nil {
		logger.Error("admin_initialization", "error", err)
		os.Exit(1)
	}
	if initialPassword != "" {
		logger.Info("initial_admin_ready", "credential_file", cfg.DataDir+"/initial-admin.txt")
	}
	api := httpapi.New(app, logger)
	server := &http.Server{Addr: cfg.ListenAddr, Handler: api.Handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	go func() {
		logger.Info("server_started", "addr", cfg.ListenAddr, "frps_public_host", cfg.FRPSPublicHost, "frps_public_port", cfg.FRPSPublicPort)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server_stopped", "error", err)
			os.Exit(1)
		}
	}()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	<-signals
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
}
