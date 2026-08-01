package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ricardo/frp-panel-platform/server/internal/acme"
	"github.com/ricardo/frp-panel-platform/server/internal/config"
	"github.com/ricardo/frp-panel-platform/server/internal/crypto"
	"github.com/ricardo/frp-panel-platform/server/internal/db"
	"github.com/ricardo/frp-panel-platform/server/internal/frps"
	"github.com/ricardo/frp-panel-platform/server/internal/httpapi"
	"github.com/ricardo/frp-panel-platform/server/internal/router"
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
	var frpsProcess *frps.Process
	if cfg.FRPSBinary != "" || cfg.FRPSBinarySHA256 != "" || cfg.FRPSConfigPath != "" {
		frpsProcess, err = frps.Start(frps.Config{Binary: cfg.FRPSBinary, SHA256: cfg.FRPSBinarySHA256, Config: cfg.FRPSConfigPath})
		if err != nil {
			logger.Error("frps_start", "error", err)
			os.Exit(1)
		}
		defer func() { _ = frpsProcess.Stop() }()
		logger.Info("frps_started", "pid", frpsProcess.PID())
	}
	if cfg.ACMEEnabled {
		provider, providerErr := acme.NewCloudflareDNS01(acme.CloudflareDNS01Config{DirectoryURL: cfg.ACMEDirectoryURL, Email: cfg.ACMEEmail, AccountKeyPath: cfg.DataDir + "/acme/account.key", CloudflareURL: cfg.CloudflareAPIBaseURL}, secrets.MasterKey)
		if providerErr != nil {
			logger.Error("acme_provider", "error", providerErr)
		} else {
			app.ACMEProvider = provider
		}
	}
	initialPassword, err := app.EnsureAdmin(context.Background())
	if err != nil {
		logger.Error("admin_initialization", "error", err)
		os.Exit(1)
	}
	if initialPassword != "" {
		logger.Info("initial_admin_ready", "credential_file", cfg.DataDir+"/initial-admin.txt")
	}
	workerCtx, cancelWorker := context.WithCancel(context.Background())
	defer cancelWorker()
	if err := app.EnqueueRouterSnapshot(context.Background()); err != nil {
		logger.Error("router_snapshot_seed", "error", err)
	}
	go func() {
		if err := app.RunJobs(workerCtx); err != nil && !errors.Is(err, context.Canceled) {
			logger.Error("job_worker_stopped", "error", err)
		}
	}()
	var routerServer *http.Server
	var cancelRouter context.CancelFunc
	if cfg.RouterListenAddr != "" {
		runtime, runtimeErr := router.NewRuntime(secrets.RouterKey, cfg.RouterControlTarget, cfg.RouterBusinessTarget)
		if runtimeErr != nil {
			logger.Error("router_runtime", "error", runtimeErr)
			os.Exit(1)
		}
		routerCtx, cancel := context.WithCancel(workerCtx)
		cancelRouter = cancel
		watcher := &router.Watcher{Runtime: runtime, SnapshotPath: filepath.Join(cfg.RouterSnapshotDir, "last-good.json"), OnError: func(watchErr error) { logger.Warn("router_snapshot_reload", "error", watchErr) }}
		go func() {
			if err := watcher.Run(routerCtx); err != nil && !errors.Is(err, context.Canceled) {
				logger.Error("router_watcher_stopped", "error", err)
			}
		}()
		routerServer = &http.Server{Addr: cfg.RouterListenAddr, Handler: runtime, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 90 * time.Second}
		go func() {
			logger.Info("router_started", "addr", cfg.RouterListenAddr, "snapshot", filepath.Join(cfg.RouterSnapshotDir, "last-good.json"))
			if err := routerServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("router_stopped", "error", err)
			}
		}()
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
	cancelWorker()
	if cancelRouter != nil {
		cancelRouter()
	}
	if routerServer != nil {
		_ = routerServer.Shutdown(ctx)
	}
	_ = server.Shutdown(ctx)
}
