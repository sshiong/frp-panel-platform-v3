package backup

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	_ "modernc.org/sqlite"
)

func TestBackupValidationAndRestoreSessionInvalidation(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, "source.db")
	database, err := sql.Open("sqlite", sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`CREATE TABLE sessions(revoked_at TEXT, revoke_reason TEXT); CREATE TABLE frp_runtime_credentials(revoked_at TEXT); CREATE TABLE system_identity(singleton_id INTEGER PRIMARY KEY, restored_from_backup_at TEXT); INSERT INTO sessions(revoked_at,revoke_reason) VALUES(NULL,NULL); INSERT INTO frp_runtime_credentials(revoked_at) VALUES(NULL); INSERT INTO system_identity(singleton_id) VALUES(1)`); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(root, "backup.fppb")
	if err := Create(context.Background(), database, archive, "backup-password-2026!"); err != nil {
		t.Fatal(err)
	}
	_ = database.Close()
	if _, _, err := DecodePackage(archive, "short"); err == nil {
		t.Fatal("short backup password was accepted")
	}
	target := filepath.Join(root, "target.db")
	targetDB, err := sql.Open("sqlite", target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := targetDB.Exec(`CREATE TABLE old(value TEXT); INSERT INTO old(value) VALUES('preserved')`); err != nil {
		t.Fatal(err)
	}
	_ = targetDB.Close()
	previous, err := Restore(archive, "backup-password-2026!", target)
	if err != nil || previous == "" {
		t.Fatalf("restore over existing target: previous=%q err=%v", previous, err)
	}
	if _, err := os.Stat(previous); err != nil {
		t.Fatal(err)
	}
	restored, err := sql.Open("sqlite", target)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	var revokeReason, restoredAt string
	if err := restored.QueryRow(`SELECT revoke_reason FROM sessions`).Scan(&revokeReason); err != nil || revokeReason != "RESTORE" {
		t.Fatalf("session restore revocation=%q err=%v", revokeReason, err)
	}
	if err := restored.QueryRow(`SELECT restored_from_backup_at FROM system_identity WHERE singleton_id=1`).Scan(&restoredAt); err != nil || restoredAt == "" {
		t.Fatalf("restore marker=%q err=%v", restoredAt, err)
	}
	if _, err := Restore(archive, "backup-password-2026!", "."); err == nil {
		t.Fatal("empty restore target was accepted")
	}
}

func TestBackupPathAndArchiveValidationEdges(t *testing.T) {
	for _, name := range []string{"", "files/", "files/../escape", "files/a\\b", "files/a//b", "wrong/file", "files/.", "files/.."} {
		if validArchiveFileName(name) {
			t.Fatalf("unsafe archive name accepted: %q", name)
		}
	}
	for _, name := range []string{"files/key", "files/nested/key", "server.db"} {
		if name != "server.db" && !validArchiveFileName(name) {
			t.Fatalf("safe archive name rejected: %q", name)
		}
	}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "backups", "logs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "logs"), 0o700); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(root, "keep.key")
	for _, path := range []string{keep, filepath.Join(root, "skip.tmp"), filepath.Join(root, "skip.db"), filepath.Join(root, "skip.log"), filepath.Join(root, "backups", "nested.key"), filepath.Join(root, "logs", "runtime.key")} {
		if err := os.WriteFile(path, []byte(path), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	files, err := collectDataFiles(root, filepath.Join(root, "out.fppb"))
	if err != nil {
		t.Fatal(err)
	}
	if string(files["files/keep.key"]) == "" || files["files/skip.tmp"] != nil || files["files/skip.db"] != nil || files["files/skip.log"] != nil {
		t.Fatalf("data file filter result=%v", files)
	}
	if err := restoreDataFiles(filepath.Join(root, "restored"), map[string][]byte{"files/../escape": []byte("bad")}); err == nil {
		t.Fatal("restore path traversal was accepted")
	}
	directoryTarget := filepath.Join(root, "directory-target")
	if err := os.MkdirAll(directoryTarget, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(directoryTarget, []byte("bad")); err == nil {
		t.Fatal("backup atomic write over a directory was accepted")
	}
	if got := migrationVersion(context.Background(), mustOpenBackupDB(t)); got != 0 {
		t.Fatalf("migration version without schema=%d", got)
	}
}

func TestRestoreFailureRollsBackInstalledDatabase(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, "source.db")
	source, err := sql.Open("sqlite", sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.Exec(`CREATE TABLE smoke(value TEXT); INSERT INTO smoke(value) VALUES('new')`); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(root, "backup.fppb")
	if err := Create(t.Context(), source, archive, "backup-password-2026!"); err != nil {
		t.Fatal(err)
	}
	_ = source.Close()

	target := filepath.Join(root, "target.db")
	old, err := sql.Open("sqlite", target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(`CREATE TABLE smoke(value TEXT); INSERT INTO smoke(value) VALUES('old')`); err != nil {
		t.Fatal(err)
	}
	_ = old.Close()
	blockedDataDir := filepath.Join(root, "blocked-data")
	if err := os.WriteFile(blockedDataDir, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := RestoreWithOptions(archive, "backup-password-2026!", target, Options{DataDir: blockedDataDir}); err == nil {
		t.Fatal("restore unexpectedly succeeded with an unavailable data directory")
	}
	rolledBack, err := sql.Open("sqlite", target)
	if err != nil {
		t.Fatal(err)
	}
	defer rolledBack.Close()
	var value string
	if err := rolledBack.QueryRow(`SELECT value FROM smoke`).Scan(&value); err != nil || value != "old" {
		t.Fatalf("database was not rolled back: value=%q err=%v", value, err)
	}
	previous, err := filepath.Glob(target + ".before-restore-*")
	if err != nil {
		t.Fatal(err)
	}
	if len(previous) != 0 {
		t.Fatalf("rollback left an orphaned previous database: %v", previous)
	}
}

func TestCreateDiskFullLeavesNoPartialArchive(t *testing.T) {
	root := os.Getenv("FRP_DISK_FULL_DIR")
	if root == "" {
		t.Skip("set FRP_DISK_FULL_DIR to a disposable full filesystem")
	}
	source, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "source.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if _, err := source.Exec(`CREATE TABLE smoke(value TEXT); INSERT INTO smoke(value) VALUES('stable')`); err != nil {
		t.Fatal(err)
	}
	fillUntilNoSpace(t, root)
	output := filepath.Join(root, "backup.fppb")
	if err := Create(t.Context(), source, output, "backup-password-2026!"); err == nil {
		t.Fatal("backup unexpectedly succeeded on a full filesystem")
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("full-disk backup left an archive: stat err=%v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() == "backup.fppb" || strings.HasPrefix(entry.Name(), ".backup-tmp-") {
			t.Fatalf("full-disk backup left a candidate file: %s", entry.Name())
		}
	}
}

func fillUntilNoSpace(t *testing.T, root string) {
	t.Helper()
	fillPath := filepath.Join(root, "fill.bin")
	fill, err := os.OpenFile(fillPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = fill.Close()
		_ = os.Remove(fillPath)
	})
	chunk := make([]byte, 1024*1024)
	for {
		if _, err := fill.Write(chunk); err != nil {
			if !errors.Is(err, syscall.ENOSPC) {
				t.Fatalf("filling disposable filesystem failed with %v, want ENOSPC", err)
			}
			break
		}
	}
	_ = fill.Close()
}

func mustOpenBackupDB(t *testing.T) *sql.DB {
	t.Helper()
	database, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "empty.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database
}
