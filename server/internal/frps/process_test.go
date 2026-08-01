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
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nsleep 30\n"), 0o700); err != nil {
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
