package main

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/ricardo/frp-panel-platform/server/internal/backup"
	_ "modernc.org/sqlite"
)

func TestRestoreValidatesInputs(t *testing.T) {
	if _, err := restore("", "long-enough-password", "target.db", ""); err == nil {
		t.Fatal("expected missing input to fail")
	}
	if _, err := restore("backup.fppb", "", "target.db", ""); err == nil {
		t.Fatal("expected missing password to fail")
	}
}

func TestRestoreInstallsBackup(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source.db")
	opened, err := sql.Open("sqlite", source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := opened.Exec("CREATE TABLE smoke(id INTEGER PRIMARY KEY, value TEXT); INSERT INTO smoke(value) VALUES ('ok')"); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(root, "backup.fppb")
	if err := backup.Create(t.Context(), opened, archive, "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	_ = opened.Close()
	target := filepath.Join(root, "target.db")
	if previous, err := restore(archive, "correct horse battery staple", target, filepath.Join(root, "data")); err != nil || previous != "" {
		t.Fatalf("restore previous=%q err=%v", previous, err)
	}
	if previous, err := restore(archive, "correct horse battery staple", target, filepath.Join(root, "data")); err != nil || previous == "" {
		t.Fatalf("second restore previous=%q err=%v", previous, err)
	}
}
