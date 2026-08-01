package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	ListenAddr       string
	DataDir          string
	Environment      string
	FRPCBinary       string
	FRPCBinarySHA256 string
	FRPCVersion      string
	AllowedHost      string
	AllowedCIDRs     []string
	AllowLAN         bool
	TLSCertFile      string
	TLSKeyFile       string
	ClientWebDir     string
}

func Load() Config {
	dataDir := getenv("FRP_CLIENT_DATA_DIR", "./data")
	return Config{
		ListenAddr:       getenv("CLIENT_LISTEN_ADDR", "127.0.0.1:7410"),
		DataDir:          filepath.Clean(dataDir),
		Environment:      getenv("FRP_PANEL_ENV", "development"),
		FRPCBinary:       os.Getenv("FRPC_BINARY"),
		FRPCBinarySHA256: os.Getenv("FRPC_BINARY_SHA256"),
		FRPCVersion:      getenv("FRPC_VERSION", "0.68.0"),
		AllowedHost:      getenv("CLIENT_ALLOWED_HOST", "127.0.0.1,localhost,[::1]"),
		AllowedCIDRs:     splitCSV(getenv("CLIENT_ALLOWED_CIDRS", "127.0.0.0/8,::1/128")),
		AllowLAN:         os.Getenv("CLIENT_ALLOW_LAN") == "true",
		TLSCertFile:      os.Getenv("CLIENT_TLS_CERT_FILE"),
		TLSKeyFile:       os.Getenv("CLIENT_TLS_KEY_FILE"),
		ClientWebDir:     os.Getenv("FRP_CLIENT_WEB_DIR"),
	}
}

// ValidateListenSecurity makes LAN exposure an explicit deployment decision.
// A non-loopback listener must be a concrete address (never 0.0.0.0/::), use
// HTTPS, and provide a CIDR allowlist in addition to the Host allowlist.
func (c Config) ValidateListenSecurity() error {
	host, _, err := net.SplitHostPort(c.ListenAddr)
	if err != nil {
		return fmt.Errorf("client listen address is invalid: %w", err)
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return fmt.Errorf("client listen address must use a literal IP")
	}
	if ip.IsUnspecified() {
		return fmt.Errorf("client listener must bind a specific address, not an unspecified address")
	}
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		return fmt.Errorf("client TLS certificate and key must be configured together")
	}
	for _, raw := range c.AllowedCIDRs {
		if _, _, err := net.ParseCIDR(raw); err != nil {
			return fmt.Errorf("client allowed CIDR %q is invalid: %w", raw, err)
		}
	}
	if ip.IsLoopback() {
		return nil
	}
	if !c.AllowLAN {
		return fmt.Errorf("non-loopback Client Panel access requires CLIENT_ALLOW_LAN=true")
	}
	if c.TLSCertFile == "" || c.TLSKeyFile == "" {
		return fmt.Errorf("LAN Client Panel access requires CLIENT_TLS_CERT_FILE and CLIENT_TLS_KEY_FILE")
	}
	if len(c.AllowedCIDRs) == 0 {
		return fmt.Errorf("LAN Client Panel access requires CLIENT_ALLOWED_CIDRS")
	}
	return nil
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

func splitCSV(value string) []string {
	items := make([]string, 0)
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			items = append(items, item)
		}
	}
	return items
}
