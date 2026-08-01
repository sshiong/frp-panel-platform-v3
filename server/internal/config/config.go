package config

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

type Config struct {
	ListenAddr         string
	DataDir            string
	DBPath             string
	MasterKeyPath      string
	ConfigSigningPath  string
	FRPSPublicHost     string
	FRPSPublicPort     int
	FRPSBindAddress    string
	FRPSBindPort       int
	Environment        string
	AdminPassword      string
	AllowedOrigins     []string
	SessionTTLHours    int
	ClientLeaseSeconds int
	PortStart          int
	PortEnd            int
	AdminWebDir        string
}

func Load() Config {
	dataDir := getenv("FRP_SERVER_DATA_DIR", "./data")
	return Config{
		ListenAddr:         getenv("SERVER_LISTEN_ADDR", "127.0.0.1:7400"),
		DataDir:            dataDir,
		DBPath:             getenv("FRP_SERVER_DB", filepath.Join(dataDir, "server.db")),
		MasterKeyPath:      getenv("FRP_SERVER_MASTER_KEY_FILE", filepath.Join(dataDir, "server-master.key")),
		ConfigSigningPath:  getenv("FRP_CONFIG_SIGNING_KEY_FILE", filepath.Join(dataDir, "config-signing.key")),
		FRPSPublicHost:     getenv("FRPS_PUBLIC_HOST", "frp.example.com"),
		FRPSPublicPort:     getenvInt("FRPS_PUBLIC_PORT", 7000),
		FRPSBindAddress:    getenv("FRPS_BIND_ADDRESS", "127.0.0.1"),
		FRPSBindPort:       getenvInt("FRPS_BIND_PORT", 7000),
		Environment:        getenv("FRP_PANEL_ENV", "development"),
		AdminPassword:      os.Getenv("FRP_ADMIN_PASSWORD"),
		AllowedOrigins:     []string{"http://127.0.0.1:5173", "http://localhost:5173", "http://127.0.0.1:7400", "http://localhost:7400"},
		SessionTTLHours:    getenvInt("FRP_SESSION_TTL_HOURS", 12),
		ClientLeaseSeconds: getenvInt("FRP_CLIENT_LEASE_SECONDS", 120),
		PortStart:          getenvInt("FRP_PORT_START", 6000),
		PortEnd:            getenvInt("FRP_PORT_END", 6999),
		AdminWebDir:        os.Getenv("FRP_ADMIN_WEB_DIR"),
	}
}

func (c Config) EnsureDirs() error {
	if err := os.MkdirAll(c.DataDir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	return nil
}

func GenerateInitialPassword() (string, error) {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func getenvInt(key string, fallback int) int {
	value, err := strconv.Atoi(os.Getenv(key))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}
