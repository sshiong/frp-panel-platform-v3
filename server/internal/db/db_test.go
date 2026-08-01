package db

import (
	"context"
	"path/filepath"
	"testing"
)

func TestOpenAppliesWALAndAllMigrations(t *testing.T) {
	database, err := Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var migrations int
	if err := database.QueryRow(`SELECT COUNT(1) FROM schema_migrations`).Scan(&migrations); err != nil || migrations != 5 {
		t.Fatalf("migrations=%d err=%v", migrations, err)
	}
	for _, table := range []string{"certificates", "router_snapshots", "router_state", "jobs", "external_residues"} {
		var name string
		if err := database.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&name); err != nil || name != table {
			t.Fatalf("missing table %s: %v", table, err)
		}
	}
	var journal string
	if err := database.QueryRow(`PRAGMA journal_mode`).Scan(&journal); err != nil || journal != "wal" {
		t.Fatalf("journal mode=%q err=%v", journal, err)
	}
}

func TestCheckpointWAL(t *testing.T) {
	database, err := Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.Checkpoint(context.Background()); err != nil {
		t.Fatal(err)
	}
}
