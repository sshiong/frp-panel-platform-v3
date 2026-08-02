package frps

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyAndStartFixedBinary(t *testing.T) {
	root := t.TempDir()
	binary := filepath.Join(root, "frps-test.sh")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nif [ \"$1\" = \"verify\" ]; then exit 0; fi\nsleep 30\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "frps.toml"), []byte("bindPort = 7000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	content, _ := os.ReadFile(binary)
	digest := sha256.Sum256(content)
	process, err := Start(Config{Binary: binary, SHA256: hex.EncodeToString(digest[:]), Config: filepath.Join(root, "frps.toml")})
	if err != nil {
		t.Fatal(err)
	}
	if process.PID() == 0 {
		t.Fatal("FRPS process should have a PID")
	}
	if err := process.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := VerifyBinary(binary, "wrong"); err == nil {
		t.Fatal("wrong FRPS checksum must fail")
	}
}

func TestProcessValidationAndNilEdges(t *testing.T) {
	if err := VerifyBinary("", ""); err == nil {
		t.Fatal("empty FRPS verification inputs were accepted")
	}
	if err := VerifyBinary(filepath.Join(t.TempDir(), "missing"), "deadbeef"); err == nil {
		t.Fatal("missing FRPS binary was accepted")
	}
	if err := VerifyConfig("", ""); err == nil {
		t.Fatal("empty FRPS config verification inputs were accepted")
	}
	if err := VerifyConfig("/bin/sh", filepath.Join(t.TempDir(), "missing.toml")); err == nil {
		t.Fatal("a failing FRPS config verifier was accepted")
	}
	if _, err := Start(Config{}); err == nil {
		t.Fatal("empty FRPS start config was accepted")
	}
	if (*Process)(nil).PID() != 0 || (&Process{}).PID() != 0 {
		t.Fatal("nil FRPS process PID was non-zero")
	}
	if err := (*Process)(nil).Stop(); err != nil {
		t.Fatal(err)
	}
	if err := (&Process{}).Stop(); err != nil {
		t.Fatal(err)
	}
}
