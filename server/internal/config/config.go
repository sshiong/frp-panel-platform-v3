package config

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	ListenAddr              string
	TLSCertFile             string
	TLSKeyFile              string
	DataDir                 string
	DBPath                  string
	MasterKeyPath           string
	ConfigSigningPath       string
	FRPSPublicHost          string
	FRPSPublicPort          int
	FRPSBindAddress         string
	FRPSBindPort            int
	FRPSBinary              string
	FRPSBinarySHA256        string
	FRPSConfigPath          string
	FRPSTransportSecretFile string
	FRPSTransportSecret     string
	Environment             string
	AdminPassword           string
	AllowedOrigins          []string
	SessionTTLHours         int
	ClientLeaseSeconds      int
	PortStart               int
	PortEnd                 int
	AdminWebDir             string
	CloudflareAPIBaseURL    string
	RouterSnapshotDir       string
	RouterListenAddr        string
	RouterTLSEnabled        bool
	RouterControlHosts      []string
	RouterControlTarget     string
	RouterBusinessTarget    string
	FRPSVhostHTTPPort       int
	ACMEEnabled             bool
	ACMEDirectoryURL        string
	ACMEEmail               string
}

func Load() Config {
	dataDir := getenv("FRP_SERVER_DATA_DIR", "./data")
	allowedOrigins := splitCSV(os.Getenv("FRP_ALLOWED_ORIGINS"))
	if len(allowedOrigins) == 0 {
		allowedOrigins = []string{
			"http://127.0.0.1:5173", "http://localhost:5173",
			"http://127.0.0.1:5174", "http://localhost:5174",
			"http://127.0.0.1:7410", "http://localhost:7410",
			"http://127.0.0.1:7400", "http://localhost:7400",
		}
	}
	return Config{
		ListenAddr:              getenv("SERVER_LISTEN_ADDR", "127.0.0.1:7400"),
		TLSCertFile:             os.Getenv("SERVER_TLS_CERT_FILE"),
		TLSKeyFile:              os.Getenv("SERVER_TLS_KEY_FILE"),
		DataDir:                 dataDir,
		DBPath:                  getenv("FRP_SERVER_DB", filepath.Join(dataDir, "server.db")),
		MasterKeyPath:           getenv("FRP_SERVER_MASTER_KEY_FILE", filepath.Join(dataDir, "server-master.key")),
		ConfigSigningPath:       getenv("FRP_CONFIG_SIGNING_KEY_FILE", filepath.Join(dataDir, "config-signing.key")),
		FRPSPublicHost:          getenv("FRPS_PUBLIC_HOST", "frp.example.com"),
		FRPSPublicPort:          getenvInt("FRPS_PUBLIC_PORT", 7000),
		FRPSBindAddress:         getenv("FRPS_BIND_ADDRESS", "127.0.0.1"),
		FRPSBindPort:            getenvInt("FRPS_BIND_PORT", 7000),
		FRPSBinary:              os.Getenv("FRPS_BINARY"),
		FRPSBinarySHA256:        os.Getenv("FRPS_BINARY_SHA256"),
		FRPSConfigPath:          os.Getenv("FRPS_CONFIG_PATH"),
		FRPSTransportSecretFile: getenv("FRPS_TRANSPORT_SECRET_FILE", filepath.Join(dataDir, "frps-transport.secret")),
		Environment:             getenv("FRP_PANEL_ENV", "development"),
		AdminPassword:           os.Getenv("FRP_ADMIN_PASSWORD"),
		AllowedOrigins:          allowedOrigins,
		SessionTTLHours:         getenvInt("FRP_SESSION_TTL_HOURS", 12),
		ClientLeaseSeconds:      getenvInt("FRP_CLIENT_LEASE_SECONDS", 120),
		PortStart:               getenvInt("FRP_PORT_START", 6000),
		PortEnd:                 getenvInt("FRP_PORT_END", 6999),
		AdminWebDir:             os.Getenv("FRP_ADMIN_WEB_DIR"),
		CloudflareAPIBaseURL:    getenv("CLOUDFLARE_API_BASE_URL", "https://api.cloudflare.com/client/v4"),
		RouterSnapshotDir:       getenv("FRP_ROUTER_SNAPSHOT_DIR", filepath.Join(dataDir, "router")),
		RouterListenAddr:        os.Getenv("FRP_ROUTER_LISTEN_ADDR"),
		RouterTLSEnabled:        os.Getenv("FRP_ROUTER_TLS_ENABLED") == "true",
		RouterControlHosts:      splitCSV(os.Getenv("FRP_ROUTER_CONTROL_HOSTS")),
		RouterControlTarget:     getenv("FRP_ROUTER_CONTROL_TARGET", "http://127.0.0.1:7400"),
		RouterBusinessTarget:    getenv("FRP_ROUTER_BUSINESS_TARGET", "http://127.0.0.1:8080"),
		FRPSVhostHTTPPort:       getenvInt("FRPS_VHOST_HTTP_PORT", 8080),
		ACMEEnabled:             os.Getenv("FRP_ACME_ENABLED") == "true",
		ACMEDirectoryURL:        getenv("FRP_ACME_DIRECTORY_URL", "https://acme-v02.api.letsencrypt.org/directory"),
		ACMEEmail:               os.Getenv("FRP_ACME_EMAIL"),
	}
}

// ValidateTransportSecurity prevents a production control plane from
// starting in plaintext or with browser origins that can downgrade requests.
// Development may intentionally use loopback HTTP for local setup.
func (c Config) ValidateTransportSecurity() error {
	if (strings.TrimSpace(c.TLSCertFile) == "") != (strings.TrimSpace(c.TLSKeyFile) == "") {
		return fmt.Errorf("server TLS certificate and key must be configured together")
	}
	if c.RouterTLSEnabled && strings.TrimSpace(c.RouterListenAddr) == "" {
		return fmt.Errorf("router TLS cannot be enabled without FRP_ROUTER_LISTEN_ADDR")
	}
	if strings.TrimSpace(c.RouterListenAddr) != "" {
		if _, _, err := net.SplitHostPort(strings.TrimSpace(c.RouterListenAddr)); err != nil {
			return fmt.Errorf("router listen address is invalid: %w", err)
		}
	}
	if strings.EqualFold(strings.TrimSpace(c.Environment), "production") {
		if strings.TrimSpace(c.TLSCertFile) == "" || strings.TrimSpace(c.TLSKeyFile) == "" {
			return fmt.Errorf("production Server Panel requires SERVER_TLS_CERT_FILE and SERVER_TLS_KEY_FILE")
		}
		if len(c.AllowedOrigins) == 0 {
			return fmt.Errorf("production Server Panel requires explicit FRP_ALLOWED_ORIGINS")
		}
		for _, origin := range c.AllowedOrigins {
			parsed, err := url.Parse(origin)
			if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
				return fmt.Errorf("production allowed origin must be an https origin: %q", origin)
			}
		}
		if strings.TrimSpace(c.RouterListenAddr) != "" && !routerListenerIsLoopback(c.RouterListenAddr) && !c.RouterTLSEnabled {
			return fmt.Errorf("production Router listener requires FRP_ROUTER_TLS_ENABLED=true")
		}
	}
	return nil
}

func routerListenerIsLoopback(address string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return false
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

// LoadOrCreateTransportSecret keeps the FRPS native auth token outside the
// database and gives it a stable, operator-controlled deployment file. The
// Server returns the value only to an authenticated Client Panel session.
func LoadOrCreateTransportSecret(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("FRPS transport secret file is required")
	}
	if value, err := readTransportSecret(path); err == nil {
		return value, nil
	} else if !os.IsNotExist(err) {
		return "", err
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", err
	}
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}
	value := base64.RawURLEncoding.EncodeToString(randomBytes)
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return "", err
	}
	temporaryName := temporary.Name()
	cleanup := func() { _ = temporary.Close(); _ = os.Remove(temporaryName) }
	defer cleanup()
	if err := temporary.Chmod(0o600); err != nil {
		return "", err
	}
	if _, err := temporary.WriteString(value + "\n"); err != nil {
		return "", err
	}
	if err := temporary.Sync(); err != nil {
		return "", err
	}
	if err := temporary.Close(); err != nil {
		return "", err
	}
	if err := os.Link(temporaryName, path); err != nil {
		if !os.IsExist(err) {
			return "", err
		}
		// Another Server process won the create race; always use its value.
		return readTransportSecret(path)
	}
	if err := syncDirectory(directory); err != nil {
		return "", err
	}
	return value, nil
}

func readTransportSecret(path string) (string, error) {
	encoded, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(encoded))
	if len(value) < 32 {
		return "", fmt.Errorf("FRPS transport secret is too short")
	}
	return value, nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
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
