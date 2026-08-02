package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateListenSecurity(t *testing.T) {
	base := Config{ListenAddr: "127.0.0.1:7410", AllowedCIDRs: []string{"127.0.0.0/8"}}
	if err := base.ValidateListenSecurity(); err != nil {
		t.Fatal(err)
	}
	for name, cfg := range map[string]Config{
		"unspecified":                  {ListenAddr: "0.0.0.0:7410", AllowedCIDRs: []string{"0.0.0.0/0"}},
		"lan requires explicit opt-in": {ListenAddr: "192.0.2.10:7410", AllowedCIDRs: []string{"192.0.2.0/24"}},
		"lan requires tls":             {ListenAddr: "192.0.2.10:7410", AllowLAN: true, AllowedCIDRs: []string{"192.0.2.0/24"}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := cfg.ValidateListenSecurity(); err == nil {
				t.Fatal("expected listener security validation failure")
			}
		})
	}
	validLAN := Config{ListenAddr: "192.0.2.10:7410", AllowLAN: true, AllowedCIDRs: []string{"192.0.2.0/24"}, TLSCertFile: "/etc/client.crt", TLSKeyFile: "/etc/client.key"}
	if err := validLAN.ValidateListenSecurity(); err != nil {
		t.Fatal(err)
	}
}

func TestLoadReadsEnvironmentAndEnsureDirs(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "client-data")
	t.Setenv("FRP_CLIENT_DATA_DIR", dataDir)
	t.Setenv("CLIENT_LISTEN_ADDR", "127.0.0.1:17410")
	t.Setenv("FRP_PANEL_ENV", "production")
	t.Setenv("FRPC_BINARY", "/opt/frpc")
	t.Setenv("FRPC_BINARY_SHA256", "abc123")
	t.Setenv("FRPC_VERSION", "0.68.0")
	t.Setenv("CLIENT_ALLOWED_HOST", "panel.example.test,127.0.0.1")
	t.Setenv("CLIENT_ALLOWED_CIDRS", "127.0.0.0/8, 192.0.2.0/24")
	t.Setenv("CLIENT_ALLOW_LAN", "true")
	t.Setenv("CLIENT_TLS_CERT_FILE", "/tmp/client.crt")
	t.Setenv("CLIENT_TLS_KEY_FILE", "/tmp/client.key")
	t.Setenv("FRP_CLIENT_WEB_DIR", "/opt/client-web")
	cfg := Load()
	if cfg.DataDir != dataDir || cfg.ListenAddr != "127.0.0.1:17410" || cfg.Environment != "production" || cfg.FRPCBinary != "/opt/frpc" || cfg.FRPCBinarySHA256 != "abc123" || len(cfg.AllowedCIDRs) != 2 || !cfg.AllowLAN || cfg.ClientWebDir != "/opt/client-web" {
		t.Fatalf("Load did not read deployment environment: %#v", cfg)
	}
	if err := cfg.EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{cfg.DataDir, filepath.Join(cfg.DataDir, "config"), filepath.Join(cfg.DataDir, "state"), filepath.Join(cfg.DataDir, "runtime", "secrets"), filepath.Join(cfg.DataDir, "logs")} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !info.IsDir() || info.Mode().Perm() != 0o700 {
			t.Fatalf("unexpected client data directory %s: mode=%o isDir=%v", path, info.Mode().Perm(), info.IsDir())
		}
	}
}
