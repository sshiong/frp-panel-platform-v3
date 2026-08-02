package db

import (
	"context"
	"os"
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
