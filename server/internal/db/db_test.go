package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenAppliesWALAndAllMigrations(t *testing.T) {
	database, err := Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var migrations int
	if err := database.QueryRow(`SELECT COUNT(1) FROM schema_migrations`).Scan(&migrations); err != nil || migrations != 7 {
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
	var instanceID string
	if err := database.QueryRow(`SELECT server_instance_id FROM system_identity WHERE singleton_id=1`).Scan(&instanceID); err != nil || instanceID == "" {
		t.Fatalf("system identity missing: id=%q err=%v", instanceID, err)
	}
}

func TestMigrationUpgradeFromPreviousStableBackup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stable-v3.0.db")
	seedStableDatabase(t, path, 6)

	database, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	var migrations int
	if err := database.QueryRow(`SELECT COUNT(1) FROM schema_migrations`).Scan(&migrations); err != nil {
		t.Fatal(err)
	}
	if migrations != 7 {
		t.Fatalf("stable backup was not upgraded: migrations=%d", migrations)
	}
	var triggerName string
	if err := database.QueryRow(`SELECT name FROM sqlite_master WHERE type='trigger' AND name=?`, "domain_bindings_http_only_redirect_insert").Scan(&triggerName); err != nil || triggerName == "" {
		t.Fatalf("latest migration trigger missing: name=%q err=%v", triggerName, err)
	}
}

func seedStableDatabase(t *testing.T, path string, latestVersion int) {
	t.Helper()
	conn, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetMaxOpenConns(1)
	defer conn.Close()
	for _, pragma := range []string{"PRAGMA foreign_keys=ON", "PRAGMA busy_timeout=5000"} {
		if _, err := conn.Exec(pragma); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := conn.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		var version int
		if _, err := fmt.Sscanf(entry.Name(), "%d_", &version); err != nil || version > latestVersion {
			continue
		}
		contents, err := migrationFS.ReadFile("migrations/" + entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		tx, err := conn.Begin()
		if err != nil {
			t.Fatal(err)
		}
		for _, statement := range strings.Split(string(contents), "-- statement") {
			statement = strings.TrimSpace(statement)
			if statement == "" {
				continue
			}
			if _, err := tx.Exec(statement); err != nil {
				_ = tx.Rollback()
				t.Fatalf("seed migration %s: %v", entry.Name(), err)
			}
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES (?, datetime('now'))`, version); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHTTPOnlyDomainRejectsRedirectAtDatabaseBoundary(t *testing.T) {
	database, err := Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	if _, err := database.Exec(`INSERT INTO users(id,username,password_hash,role,status,created_at,updated_at) VALUES('db-user','db-user','hash','user','active',datetime('now'),datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO mappings(id,user_id,name,proxy_type,lifecycle_status,desired_state,observed_state,created_at,updated_at) VALUES('db-map','db-user','db-map','http','reserved','enabled','offline',datetime('now'),datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	domainInsert := `INSERT INTO domain_bindings(id,user_id,mapping_id,hostname,normalized_domain,https_mode,http_redirect,status,revision,created_at,updated_at) VALUES('db-domain','db-user','db-map','db.example.com','db.example.com','http_only',1,'pending_dns',1,datetime('now'),datetime('now'))`
	if _, err := database.Exec(domainInsert); err == nil {
		t.Fatal("database accepted http_only redirect")
	}
	if _, err := database.Exec(`INSERT INTO domain_bindings(id,user_id,mapping_id,hostname,normalized_domain,https_mode,http_redirect,status,revision,created_at,updated_at) VALUES('db-domain','db-user','db-map','db.example.com','db.example.com','http_only',0,'pending_dns',1,datetime('now'),datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE domain_bindings SET http_redirect=1 WHERE id='db-domain'`); err == nil {
		t.Fatal("database accepted http_only redirect update")
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

func TestCheckpointUnderWALPressure(t *testing.T) {
	root := os.Getenv("FRP_WAL_PRESSURE_DIR")
	if root == "" {
		t.Skip("set FRP_WAL_PRESSURE_DIR to a disposable filesystem")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "wal-pressure.db")
	database, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`PRAGMA wal_autocheckpoint=1000000; CREATE TABLE wal_pressure(id INTEGER PRIMARY KEY, payload TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	tx, err := database.Begin()
	if err != nil {
		t.Fatal(err)
	}
	payload := strings.Repeat("w", 2048)
	for index := 0; index < 2000; index++ {
		if _, err := tx.Exec(`INSERT INTO wal_pressure(payload) VALUES(?)`, payload); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	walPath := path + "-wal"
	walInfo, err := os.Stat(walPath)
	if err != nil {
		t.Fatalf("WAL pressure did not produce a WAL file: err=%v", err)
	}
	if walInfo.Size() == 0 {
		t.Fatalf("WAL pressure produced an empty WAL file")
	}
	if err := database.Checkpoint(context.Background()); err != nil {
		t.Fatal(err)
	}
	if walInfo, err := os.Stat(walPath); err == nil && walInfo.Size() != 0 {
		t.Fatalf("checkpoint did not truncate WAL: size=%d", walInfo.Size())
	}
	var count int
	if err := database.QueryRow(`SELECT COUNT(1) FROM wal_pressure`).Scan(&count); err != nil || count != 2000 {
		t.Fatalf("checkpoint changed durable rows: count=%d err=%v", count, err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.QueryRow(`SELECT COUNT(1) FROM wal_pressure`).Scan(&count); err != nil || count != 2000 {
		t.Fatalf("restart lost WAL rows: count=%d err=%v", count, err)
	}
}

func TestOpenRejectsUnavailableDatabaseParent(t *testing.T) {
	root := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(root, []byte("blocker"), 0o600); err != nil {
		t.Fatal(err)
	}
	if database, err := Open(filepath.Join(root, "server.db")); err == nil {
		_ = database.Close()
		t.Fatal("database below a regular-file parent was accepted")
	}
}
