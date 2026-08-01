package config

import (
	"os"
	"path/filepath"
	"testing"
)

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
