package service

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/ricardo/frp-panel-platform/server/internal/config"
	"github.com/ricardo/frp-panel-platform/server/internal/crypto"
	"github.com/ricardo/frp-panel-platform/server/internal/db"
)

func newUserDeletionFixture(t *testing.T) (*App, *db.DB, AuthContext, AuthContext) {
	t.Helper()
	root := t.TempDir()
	database, err := db.Open(filepath.Join(root, "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	secrets, err := crypto.Load(root, filepath.Join(root, "master.key"), filepath.Join(root, "signing.key"))
	if err != nil {
		t.Fatal(err)
	}
	app := New(database, config.Config{DataDir: root, Environment: "development", AdminPassword: "Admin-Password-2026!", SessionTTLHours: 12, PortStart: 6000, PortEnd: 6999}, secrets)
	if _, err := app.EnsureAdmin(context.Background()); err != nil {
		t.Fatal(err)
	}
	adminLogin, err := app.Login(context.Background(), "admin", "Admin-Password-2026!", "admin_panel", "127.0.0.1", "test")
	if err != nil {
		t.Fatal(err)
	}
	admin, err := app.Authenticate(context.Background(), adminLogin.Token)
	if err != nil {
		t.Fatal(err)
	}
	_, password, err := app.CreateUser(context.Background(), admin, "alice")
	if err != nil {
		t.Fatal(err)
	}
	clientLogin, err := app.Login(context.Background(), "alice", password, "client_panel", "127.0.0.1", "test")
	if err != nil {
		t.Fatal(err)
	}
	user, err := app.Authenticate(context.Background(), clientLogin.Token)
	if err != nil {
		t.Fatal(err)
	}
	return app, database, admin, user
}

func claimJobType(t *testing.T, app *App, expected string) {
	t.Helper()
	for {
		job, err := app.Jobs.Claim(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if job.Type != expected {
			if err := app.handleJob(context.Background(), job); err != nil {
				t.Fatal(err)
			}
			if err := app.Jobs.Complete(context.Background(), job.ID); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := app.handleJob(context.Background(), job); err != nil {
			t.Fatal(err)
		}
		if err := app.Jobs.Complete(context.Background(), job.ID); err != nil {
			t.Fatal(err)
		}
		return
	}
}

func TestUserDeletionRemovesLocalResourcesAfterRevocation(t *testing.T) {
	app, database, admin, user := newUserDeletionFixture(t)
	mapping, err := app.CreateMapping(context.Background(), user, MappingRequest{Name: "delete-me", ProxyType: "tcp", LocalIP: "127.0.0.1", LocalPort: 8080}, "user-delete-map-123456")
	if err != nil {
		t.Fatal(err)
	}
	opID, err := app.DeleteUser(context.Background(), admin, user.UserID, false, "user-delete-key-123456")
	if err != nil {
		t.Fatal(err)
	}
	if repeated, err := app.DeleteUser(context.Background(), admin, user.UserID, false, "user-delete-key-123456"); err != nil || repeated != opID {
		t.Fatalf("user delete idempotency: first=%q repeated=%q err=%v", opID, repeated, err)
	}
	if _, err := app.Authenticate(context.Background(), "invalid-token"); err == nil {
		t.Fatal("invalid token unexpectedly authenticated")
	}
	if err := app.seedPendingJobs(context.Background()); err != nil {
		t.Fatal("restart seeding should not block on SQLite rows: ", err)
	}
	var status string
	if err := database.QueryRow(`SELECT status FROM users WHERE id=?`, user.UserID).Scan(&status); err != nil || status != "deleting" {
		t.Fatalf("user was not moved to deleting: %q %v", status, err)
	}
	claimJobType(t, app, "user_delete")
	var users, mappings int
	if err := database.QueryRow(`SELECT COUNT(1) FROM users WHERE id=?`, user.UserID).Scan(&users); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT COUNT(1) FROM mappings WHERE id=?`, mapping.ID).Scan(&mappings); err != nil {
		t.Fatal(err)
	}
	if users != 0 || mappings != 0 {
		t.Fatalf("local deletion incomplete: users=%d mappings=%d", users, mappings)
	}
	var operationStatus, operationOwner string
	if err := database.QueryRow(`SELECT status,COALESCE(user_id,'') FROM operations WHERE id=?`, opID).Scan(&operationStatus, &operationOwner); err != nil {
		t.Fatal(err)
	}
	if operationStatus != "succeeded" || operationOwner != "" {
		t.Fatalf("user operation was not retained after deletion: status=%q owner=%q", operationStatus, operationOwner)
	}
}

func TestForcedUserDeletionRecordsExternalResidue(t *testing.T) {
	app, database, admin, user := newUserDeletionFixture(t)
	mapping, err := app.CreateMapping(context.Background(), user, MappingRequest{Name: "domain-delete-me", ProxyType: "http", LocalIP: "127.0.0.1", LocalPort: 8080}, "user-force-map-123456")
	if err != nil {
		t.Fatal(err)
	}
	domain, err := app.CreateDomain(context.Background(), user, DomainRequest{MappingID: mapping.ID, Hostname: "delete.example.com", HTTPSMode: "http_only"}, "user-force-domain-123456")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE jobs SET status='canceled',completed_at=? WHERE status IN ('pending','retry_wait','running')`, nowString()); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO dns_records(id,user_id,domain_binding_id,type,name,normalized_name,content,ttl,proxied,zone_id,record_id,managed_by_panel,adopted,locked,sync_status,last_synced_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, uuid.NewString(), user.UserID, domain.ID, "CNAME", "delete.example.com", "delete.example.com", "frp.example.com", 300, 0, "zone-1", "record-1", 1, 0, 0, "synced", nowString()); err != nil {
		t.Fatal(err)
	}
	opID, err := app.DeleteUser(context.Background(), admin, user.UserID, false, "user-delete-key-123456")
	if err != nil {
		t.Fatal(err)
	}
	failingJob, err := app.Jobs.Claim(context.Background())
	if err != nil || failingJob.Type != "user_delete" {
		t.Fatalf("non-force delete job: %#v %v", failingJob, err)
	}
	if err := app.handleJob(context.Background(), failingJob); err == nil {
		t.Fatal("non-force deletion should remain local when external cleanup is unavailable")
	}
	if _, err := database.Exec(`UPDATE jobs SET status='retry_wait',run_after=?,lock_owner=NULL,lock_expires_at=NULL WHERE id=?`, nowString(), failingJob.ID); err != nil {
		t.Fatal(err)
	}
	forcedOperation, err := app.DeleteUser(context.Background(), admin, user.UserID, true, "user-force-delete-key-123456")
	if err != nil || forcedOperation != opID {
		t.Fatalf("force escalation should reuse deletion operation: operation=%q expected=%q err=%v", forcedOperation, opID, err)
	}
	claimJobType(t, app, "user_delete")
	var residueCount int
	if err := database.QueryRow(`SELECT COUNT(1) FROM external_residues WHERE operation_id=?`, opID).Scan(&residueCount); err != nil {
		t.Fatal(err)
	}
	if residueCount != 1 {
		t.Fatalf("forced deletion did not record external residue: %d", residueCount)
	}
	operations, err := app.Operations(context.Background(), admin.UserID, true)
	if err != nil {
		t.Fatal(err)
	}
	var residueVisible bool
	for _, operation := range operations {
		if operation["id"] == opID {
			items, ok := operation["external_residues"].([]map[string]interface{})
			residueVisible = ok && len(items) == 1 && items[0]["provider"] == "cloudflare"
		}
	}
	if !residueVisible {
		t.Fatal("forced deletion did not expose the external residue list")
	}
	var auditCount int
	if err := database.QueryRow(`SELECT COUNT(1) FROM audit_logs WHERE action='user_delete_external_residue' AND operation_id=?`, opID).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("forced deletion audit evidence: count=%d err=%v", auditCount, err)
	}
	var operationStatus, compensationStatus string
	if err := database.QueryRow(`SELECT status,compensation_status FROM operations WHERE id=?`, opID).Scan(&operationStatus, &compensationStatus); err != nil {
		t.Fatal(err)
	}
	if operationStatus != "succeeded" || compensationStatus != "external_residue" {
		t.Fatalf("forced deletion outcome: status=%q compensation=%q", operationStatus, compensationStatus)
	}
	var userCount int
	if err := database.QueryRow(`SELECT COUNT(1) FROM users WHERE id=?`, user.UserID).Scan(&userCount); err != nil {
		t.Fatal(err)
	}
	if userCount != 0 {
		t.Fatal("forced deletion kept the local user row")
	}
}
