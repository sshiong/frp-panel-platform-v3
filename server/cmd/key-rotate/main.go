package main

import (
	"context"
	"fmt"
	"os"

	"github.com/ricardo/frp-panel-platform/server/internal/config"
	"github.com/ricardo/frp-panel-platform/server/internal/crypto"
	"github.com/ricardo/frp-panel-platform/server/internal/db"
	"github.com/ricardo/frp-panel-platform/server/internal/service"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	cfg := config.Load()
	if err := cfg.EnsureDirs(); err != nil {
		return fmt.Errorf("ensure data directories: %w", err)
	}
	database, err := db.Open(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer database.Close()
	secrets, err := crypto.Load(cfg.DataDir, cfg.MasterKeyPath, cfg.ConfigSigningPath)
	if err != nil {
		return fmt.Errorf("load encryption keys: %w", err)
	}
	result, err := service.New(database, cfg, secrets).RotateEncryptionKeys(context.Background())
	if err != nil {
		return fmt.Errorf("rotate encryption keys: %w", err)
	}
	fmt.Printf("Encryption key rotation completed: master_key_version=%d certificate_key_version=%d frp_credentials=%d cloudflare_credentials=%d certificates=%d\n", result.MasterKeyVersion, result.CertificateKeyVersion, result.FRPCredentials, result.CloudflareCredentials, result.Certificates)
	return nil
}
