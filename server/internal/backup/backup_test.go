package backup

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestCreateDecodeAndRestore(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "server-data")
	if err := os.MkdirAll(filepath.Join(dataDir, "backups"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "server-master.key"), []byte("master-secret-material"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "backups", "old.fppb"), []byte("must-not-be-nested"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "source.db")
	db, err := sql.Open("sqlite", source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE smoke(id INTEGER PRIMARY KEY, value TEXT); INSERT INTO smoke(value) VALUES ('ok')`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(root, "backup.fppb")
	opened, err := sql.Open("sqlite", source)
	if err != nil {
		t.Fatal(err)
	}
	if err := CreateWithOptions(t.Context(), opened, archive, "correct horse battery staple", Options{DataDir: dataDir}); err != nil {
		t.Fatal(err)
	}
	_ = opened.Close()
	if _, _, err := Decode(archive, "wrong password"); err == nil {
		t.Fatal("wrong password should fail")
	}
	manifest, snapshot, err := Decode(archive, "correct horse battery staple")
	if err != nil || manifest.Format != "frp-panel-backup-v1" || len(snapshot) == 0 {
		t.Fatalf("decode: %#v %d %v", manifest, len(snapshot), err)
	}
	_, files, err := DecodePackage(archive, "correct horse battery staple")
	if err != nil || string(files["files/server-master.key"]) != "master-secret-material" {
		t.Fatalf("protected files were not archived: files=%v err=%v", len(files), err)
	}
	if _, ok := files["files/backups/old.fppb"]; ok {
		t.Fatal("nested backup archive must not be included")
	}
	target := filepath.Join(root, "restored.db")
	restoredDataDir := filepath.Join(root, "restored-data")
	previous, err := RestoreWithOptions(archive, "correct horse battery staple", target, Options{DataDir: restoredDataDir})
	if err != nil || previous != "" {
		t.Fatalf("restore: previous=%q err=%v", previous, err)
	}
	restored, err := sql.Open("sqlite", target)
	if err != nil {
		t.Fatal(err)
	}
	var value string
	if err := restored.QueryRow("SELECT value FROM smoke WHERE id=1").Scan(&value); err != nil || value != "ok" {
		t.Fatalf("restored value: %q %v", value, err)
	}
	_ = restored.Close()
	key, err := os.ReadFile(filepath.Join(restoredDataDir, "server-master.key"))
	if err != nil || string(key) != "master-secret-material" {
		t.Fatalf("restored key: %q %v", key, err)
	}
	if _, err := os.Stat(archive); err != nil {
		t.Fatal(err)
	}
}
