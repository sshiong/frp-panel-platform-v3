package main

import (
	"path/filepath"
	"testing"
)

func TestRunCheckpoint(t *testing.T) {
	if err := run(""); err == nil {
		t.Fatal("expected empty database path to fail")
	}
	if err := run(filepath.Join(t.TempDir(), "server.db")); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
}
