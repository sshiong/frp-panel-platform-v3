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
	if err := Create(t.Context(), opened, archive, "correct horse battery staple"); err != nil {
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
	target := filepath.Join(root, "restored.db")
	previous, err := Restore(archive, "correct horse battery staple", target)
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
	if _, err := os.Stat(archive); err != nil {
		t.Fatal(err)
	}
}
