package config

import (
	"os"
	"path/filepath"
)

type Config struct {
	ListenAddr   string
	DataDir      string
	Environment  string
	FRPCBinary   string
	AllowedHost  string
	ClientWebDir string
}

func Load() Config {
	dataDir := getenv("FRP_CLIENT_DATA_DIR", "./data")
	return Config{
		ListenAddr:   getenv("CLIENT_LISTEN_ADDR", "127.0.0.1:7410"),
		DataDir:      filepath.Clean(dataDir),
		Environment:  getenv("FRP_PANEL_ENV", "development"),
		FRPCBinary:   os.Getenv("FRPC_BINARY"),
		AllowedHost:  getenv("CLIENT_ALLOWED_HOST", "127.0.0.1"),
		ClientWebDir: os.Getenv("FRP_CLIENT_WEB_DIR"),
	}
}

func (c Config) EnsureDirs() error {
	for _, path := range []string{c.DataDir, filepath.Join(c.DataDir, "config"), filepath.Join(c.DataDir, "state"), filepath.Join(c.DataDir, "runtime", "secrets"), filepath.Join(c.DataDir, "logs")} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return err
		}
	}
	return nil
}

func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
