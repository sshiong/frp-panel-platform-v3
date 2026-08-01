package service

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/ricardo/frp-panel-platform/server/internal/config"
	"github.com/ricardo/frp-panel-platform/server/internal/crypto"
	"github.com/ricardo/frp-panel-platform/server/internal/db"
)

func TestWriteActionsAreIdempotent(t *testing.T) {
	root := t.TempDir()
	database, err := db.Open(filepath.Join(root, "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	secrets, err := crypto.Load(root, filepath.Join(root, "master.key"), filepath.Join(root, "signing.key"))
	if err != nil {
		t.Fatal(err)
	}
	app := New(database, config.Config{
		DataDir:         root,
		Environment:     "development",
		AdminPassword:   "Admin-Password-2026!",
		SessionTTLHours: 12,
		PortStart:       6000,
		PortEnd:         6999,
	}, secrets)
	if _, err := app.EnsureAdmin(context.Background()); err != nil {
		t.Fatal(err)
	}
	admin, err := app.Login(context.Background(), "admin", "Admin-Password-2026!", "admin_panel", "127.0.0.1", "test")
	if err != nil {
		t.Fatal(err)
	}
	_, initialPassword, err := app.CreateUser(context.Background(), AuthContext{UserID: admin.User.ID, Role: "admin", SessionID: admin.SessionID, Generation: 1}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	login, err := app.Login(context.Background(), "alice", initialPassword, "client_panel", "127.0.0.1", "test")
	if err != nil {
		t.Fatal(err)
	}
	user, err := app.Authenticate(context.Background(), login.Token)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.ChangePassword(context.Background(), user, initialPassword, "Alice-Password-2026!"); err != nil {
		t.Fatal(err)
	}

	mapping, err := app.CreateMapping(context.Background(), user, MappingRequest{Name: "web", ProxyType: "http", LocalIP: "127.0.0.1", LocalPort: 8080}, "mapping-create-key-123456")
	if err != nil {
		t.Fatal(err)
	}
	toggleOptions := ToggleMappingOptions{IdempotencyKey: "mapping-toggle-key-123456"}
	if err := app.ToggleMapping(context.Background(), user, mapping.ID, false, toggleOptions); err != nil {
		t.Fatal(err)
	}
	if err := app.ToggleMapping(context.Background(), user, mapping.ID, false, toggleOptions); err != nil {
		t.Fatal(err)
	}
	var desiredState string
	var desiredVersion int64
	if err := database.QueryRow(`SELECT m.desired_state,u.desired_config_version FROM mappings m JOIN users u ON u.id=m.user_id WHERE m.id=?`, mapping.ID).Scan(&desiredState, &desiredVersion); err != nil {
		t.Fatal(err)
	}
	if desiredState != "disabled" || desiredVersion != 2 {
		t.Fatalf("toggle was applied more than once: state=%q version=%d", desiredState, desiredVersion)
	}
	if err := app.ToggleMapping(context.Background(), user, mapping.ID, true, toggleOptions); err != ErrIdempotencyReuse {
		t.Fatalf("expected toggle idempotency conflict, got %v", err)
	}

	domain, err := app.CreateDomain(context.Background(), user, DomainRequest{MappingID: mapping.ID, Hostname: "app.example.com", HTTPSMode: "http_only"}, "domain-create-key-123456")
	if err != nil {
		t.Fatal(err)
	}
	if err := app.ResolveDomainDNS(context.Background(), user, domain.ID, "adopt", "dns-action-key-123456"); err != nil {
		t.Fatal(err)
	}
	if err := app.ResolveDomainDNS(context.Background(), user, domain.ID, "adopt", "dns-action-key-123456"); err != nil {
		t.Fatal(err)
	}
	var dnsJobs int
	if err := database.QueryRow(`SELECT COUNT(1) FROM jobs WHERE type='domain_dns_sync' AND deduplication_key=?`, "domain:"+domain.ID+":dns").Scan(&dnsJobs); err != nil {
		t.Fatal(err)
	}
	if dnsJobs != 1 {
		t.Fatalf("DNS action was not deduplicated: %d", dnsJobs)
	}

	firstDelete, err := app.DeleteDomain(context.Background(), user, domain.ID, "domain-delete-key-123456")
	if err != nil {
		t.Fatal(err)
	}
	secondDelete, err := app.DeleteDomain(context.Background(), user, domain.ID, "domain-delete-key-123456")
	if err != nil || firstDelete != secondDelete {
		t.Fatalf("domain deletion was not deduplicated: first=%q second=%q err=%v", firstDelete, secondDelete, err)
	}
	var deleteOperations int
	if err := database.QueryRow(`SELECT COUNT(1) FROM operations WHERE resource_type='domain' AND resource_id=? AND operation_type='delete'`, domain.ID).Scan(&deleteOperations); err != nil {
		t.Fatal(err)
	}
	if deleteOperations != 1 {
		t.Fatalf("duplicate domain delete operation: %d", deleteOperations)
	}
}
