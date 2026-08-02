package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/ricardo/frp-panel-platform/server/internal/config"
)

func TestRunStartsAndStopsDevelopmentStack(t *testing.T) {
	root := t.TempDir()
	cfg := config.Config{
		ListenAddr:              "127.0.0.1:0",
		DataDir:                 root,
		DBPath:                  filepath.Join(root, "server.db"),
		MasterKeyPath:           filepath.Join(root, "server-master.key"),
		ConfigSigningPath:       filepath.Join(root, "config-signing.key"),
		FRPSTransportSecretFile: filepath.Join(root, "frps-transport.secret"),
		Environment:             "development",
		AdminPassword:           "Admin-Password-2026!",
		AllowedOrigins:          []string{"http://127.0.0.1:5173"},
		SessionTTLHours:         12,
		ClientLeaseSeconds:      120,
		PortStart:               6000,
		PortEnd:                 6999,
		FRPSPublicHost:          "frp.example.com",
		FRPSPublicPort:          7000,
		RouterSnapshotDir:       filepath.Join(root, "router"),
		RouterListenAddr:        "127.0.0.1:0",
		RouterControlTarget:     "http://127.0.0.1:7400",
		RouterBusinessTarget:    "http://127.0.0.1:8080",
		FRPSVhostHTTPPort:       8080,
	}
	signals := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() { done <- run(cfg, signals) }()

	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(cfg.DBPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("server did not initialize its database")
		}
		time.Sleep(25 * time.Millisecond)
	}
	signals <- syscall.SIGTERM

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop after SIGTERM")
	}
}

func TestRunRejectsInvalidTransportConfiguration(t *testing.T) {
	cfg := config.Config{TLSCertFile: "only-cert.pem", Environment: "development"}
	if err := run(cfg, make(chan os.Signal, 1)); err == nil {
		t.Fatal("expected invalid TLS pair to be rejected")
	}
}

func TestRunRejectsStartupDependencyFailures(t *testing.T) {
	root := t.TempDir()
	base := config.Config{
		ListenAddr:              "127.0.0.1:0",
		DataDir:                 root,
		DBPath:                  filepath.Join(root, "server.db"),
		MasterKeyPath:           filepath.Join(root, "server-master.key"),
		ConfigSigningPath:       filepath.Join(root, "config-signing.key"),
		FRPSTransportSecretFile: filepath.Join(root, "frps-transport.secret"),
		Environment:             "development",
		AdminPassword:           "Admin-Password-2026!",
		PortStart:               6000,
		PortEnd:                 6999,
		FRPSPublicHost:          "frp.example.com",
		FRPSPublicPort:          7000,
	}
	blocked := filepath.Join(root, "blocked")
	if err := os.WriteFile(blocked, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	invalidDataDir := base
	invalidDataDir.DataDir = filepath.Join(blocked, "data")
	if err := run(invalidDataDir, make(chan os.Signal, 1)); err == nil {
		t.Fatal("invalid data directory was accepted")
	}
	invalidSecret := base
	invalidSecret.FRPSTransportSecretFile = filepath.Join(blocked, "transport.secret")
	if err := run(invalidSecret, make(chan os.Signal, 1)); err == nil {
		t.Fatal("unavailable transport secret path was accepted")
	}
	invalidFRPS := base
	invalidFRPS.FRPSBinary = "/bin/sh"
	invalidFRPS.FRPSBinarySHA256 = "wrong-checksum"
	invalidFRPS.FRPSConfigPath = filepath.Join(root, "frps.toml")
	if err := run(invalidFRPS, make(chan os.Signal, 1)); err == nil {
		t.Fatal("invalid FRPS binary checksum was accepted")
	}
}
