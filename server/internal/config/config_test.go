package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateTransportSecurity(t *testing.T) {
	base := Config{Environment: "production", TLSCertFile: "/etc/panel/cert.pem", TLSKeyFile: "/etc/panel/key.pem", AllowedOrigins: []string{"https://panel.example.com"}}
	if err := base.ValidateTransportSecurity(); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []Config{
		{Environment: "production", AllowedOrigins: []string{"https://panel.example.com"}},
		{Environment: "production", TLSCertFile: "/etc/panel/cert.pem", TLSKeyFile: "/etc/panel/key.pem", AllowedOrigins: []string{"http://panel.example.com"}},
		{Environment: "production", TLSCertFile: "/etc/panel/cert.pem", AllowedOrigins: []string{"https://panel.example.com"}},
	} {
		if err := invalid.ValidateTransportSecurity(); err == nil {
			t.Fatalf("invalid production transport config was accepted: %#v", invalid)
		}
	}
	if err := (Config{Environment: "development", AllowedOrigins: []string{"http://127.0.0.1:5173"}}).ValidateTransportSecurity(); err != nil {
		t.Fatal(err)
	}
	if err := (Config{Environment: "production", TLSCertFile: "/etc/panel/cert.pem", TLSKeyFile: "/etc/panel/key.pem", AllowedOrigins: []string{"https://panel.example.com"}, RouterListenAddr: "0.0.0.0:7443", RouterTLSEnabled: true}).ValidateTransportSecurity(); err != nil {
		t.Fatal(err)
	}
	if err := (Config{Environment: "production", TLSCertFile: "/etc/panel/cert.pem", TLSKeyFile: "/etc/panel/key.pem", AllowedOrigins: []string{"https://panel.example.com"}, RouterListenAddr: "127.0.0.1:7443"}).ValidateTransportSecurity(); err != nil {
		t.Fatal(err)
	}
	for name, invalid := range map[string]Config{
		"router plaintext in production": {Environment: "production", TLSCertFile: "/etc/panel/cert.pem", TLSKeyFile: "/etc/panel/key.pem", AllowedOrigins: []string{"https://panel.example.com"}, RouterListenAddr: "0.0.0.0:7443"},
		"router TLS without listener":    {Environment: "development", RouterTLSEnabled: true},
		"router invalid address":         {Environment: "development", RouterListenAddr: "not-an-address"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := invalid.ValidateTransportSecurity(); err == nil {
				t.Fatal("invalid Router TLS configuration was accepted")
			}
		})
	}
}

func TestLoadOrCreateTransportSecretIsStableAndPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "frps-transport.secret")
	first, err := LoadOrCreateTransportSecret(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreateTransportSecret(path)
	if err != nil {
		t.Fatal(err)
	}
	if first == "" || first != second {
		t.Fatalf("transport secret was not stable: first=%q second=%q", first, second)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("transport secret mode is not private: %o", info.Mode().Perm())
	}
	if err := os.WriteFile(path, []byte("short\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateTransportSecret(path); err == nil {
		t.Fatal("short transport secret was accepted")
	}
}

func TestLoadReadsDeploymentEnvironmentAndEnsureDirs(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "panel-data")
	t.Setenv("FRP_SERVER_DATA_DIR", dataDir)
	t.Setenv("SERVER_LISTEN_ADDR", "127.0.0.1:17400")
	t.Setenv("SERVER_TLS_CERT_FILE", "/tmp/server.crt")
	t.Setenv("SERVER_TLS_KEY_FILE", "/tmp/server.key")
	t.Setenv("FRP_ALLOWED_ORIGINS", "https://panel.example.test, https://admin.example.test")
	t.Setenv("FRP_SESSION_TTL_HOURS", "24")
	t.Setenv("FRP_PORT_START", "6100")
	t.Setenv("FRP_PORT_END", "6199")
	t.Setenv("FRP_ROUTER_LISTEN_ADDR", "127.0.0.1:17443")
	t.Setenv("FRP_ROUTER_TLS_ENABLED", "true")
	t.Setenv("FRP_ACME_ENABLED", "true")
	cfg := Load()
	if cfg.DataDir != dataDir || cfg.DBPath != filepath.Join(dataDir, "server.db") || cfg.ListenAddr != "127.0.0.1:17400" || cfg.SessionTTLHours != 24 || cfg.PortStart != 6100 || cfg.PortEnd != 6199 || len(cfg.AllowedOrigins) != 2 || !cfg.RouterTLSEnabled || !cfg.ACMEEnabled {
		t.Fatalf("Load did not read deployment environment: %#v", cfg)
	}
	if err := cfg.EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("unexpected data directory: mode=%o isDir=%v", info.Mode().Perm(), info.IsDir())
	}
	password, err := GenerateInitialPassword()
	if err != nil {
		t.Fatal(err)
	}
	if len(password) < 20 {
		t.Fatalf("generated password is unexpectedly short: %d", len(password))
	}
}
