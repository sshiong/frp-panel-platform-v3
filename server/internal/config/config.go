package config

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	ListenAddr           string
	DataDir              string
	DBPath               string
	MasterKeyPath        string
	ConfigSigningPath    string
	FRPSPublicHost       string
	FRPSPublicPort       int
	FRPSBindAddress      string
	FRPSBindPort         int
	FRPSBinary           string
	FRPSBinarySHA256     string
	FRPSConfigPath       string
	Environment          string
	AdminPassword        string
	AllowedOrigins       []string
	SessionTTLHours      int
	ClientLeaseSeconds   int
	PortStart            int
	PortEnd              int
	AdminWebDir          string
	CloudflareAPIBaseURL string
	RouterSnapshotDir    string
	RouterControlHosts   []string
	RouterControlTarget  string
	RouterBusinessTarget string
	FRPSVhostHTTPPort    int
	ACMEEnabled          bool
	ACMEDirectoryURL     string
	ACMEEmail            string
}

func Load() Config {
	dataDir := getenv("FRP_SERVER_DATA_DIR", "./data")
	allowedOrigins := splitCSV(os.Getenv("FRP_ALLOWED_ORIGINS"))
	if len(allowedOrigins) == 0 {
		allowedOrigins = []string{"http://127.0.0.1:5173", "http://localhost:5173", "http://127.0.0.1:7400", "http://localhost:7400"}
	}
	return Config{
		ListenAddr:           getenv("SERVER_LISTEN_ADDR", "127.0.0.1:7400"),
		DataDir:              dataDir,
		DBPath:               getenv("FRP_SERVER_DB", filepath.Join(dataDir, "server.db")),
		MasterKeyPath:        getenv("FRP_SERVER_MASTER_KEY_FILE", filepath.Join(dataDir, "server-master.key")),
		ConfigSigningPath:    getenv("FRP_CONFIG_SIGNING_KEY_FILE", filepath.Join(dataDir, "config-signing.key")),
		FRPSPublicHost:       getenv("FRPS_PUBLIC_HOST", "frp.example.com"),
		FRPSPublicPort:       getenvInt("FRPS_PUBLIC_PORT", 7000),
		FRPSBindAddress:      getenv("FRPS_BIND_ADDRESS", "127.0.0.1"),
		FRPSBindPort:         getenvInt("FRPS_BIND_PORT", 7000),
		FRPSBinary:           os.Getenv("FRPS_BINARY"),
		FRPSBinarySHA256:     os.Getenv("FRPS_BINARY_SHA256"),
		FRPSConfigPath:       os.Getenv("FRPS_CONFIG_PATH"),
		Environment:          getenv("FRP_PANEL_ENV", "development"),
		AdminPassword:        os.Getenv("FRP_ADMIN_PASSWORD"),
		AllowedOrigins:       allowedOrigins,
		SessionTTLHours:      getenvInt("FRP_SESSION_TTL_HOURS", 12),
		ClientLeaseSeconds:   getenvInt("FRP_CLIENT_LEASE_SECONDS", 120),
		PortStart:            getenvInt("FRP_PORT_START", 6000),
		PortEnd:              getenvInt("FRP_PORT_END", 6999),
		AdminWebDir:          os.Getenv("FRP_ADMIN_WEB_DIR"),
		CloudflareAPIBaseURL: getenv("CLOUDFLARE_API_BASE_URL", "https://api.cloudflare.com/client/v4"),
		RouterSnapshotDir:    getenv("FRP_ROUTER_SNAPSHOT_DIR", filepath.Join(dataDir, "router")),
		RouterControlHosts:   splitCSV(os.Getenv("FRP_ROUTER_CONTROL_HOSTS")),
		RouterControlTarget:  getenv("FRP_ROUTER_CONTROL_TARGET", "http://127.0.0.1:7400"),
		RouterBusinessTarget: getenv("FRP_ROUTER_BUSINESS_TARGET", "http://127.0.0.1:8080"),
		FRPSVhostHTTPPort:    getenvInt("FRPS_VHOST_HTTP_PORT", 8080),
		ACMEEnabled:          os.Getenv("FRP_ACME_ENABLED") == "true",
		ACMEDirectoryURL:     getenv("FRP_ACME_DIRECTORY_URL", "https://acme-v02.api.letsencrypt.org/directory"),
		ACMEEmail:            os.Getenv("FRP_ACME_EMAIL"),
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

func splitCSV(value string) []string {
	items := make([]string, 0)
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			items = append(items, item)
		}
	}
	return items
}
