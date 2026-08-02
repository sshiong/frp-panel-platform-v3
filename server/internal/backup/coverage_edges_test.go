package backup

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
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

func mustOpenBackupDB(t *testing.T) *sql.DB {
	t.Helper()
	database, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "empty.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database
}
