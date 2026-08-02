package service

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/ricardo/frp-panel-platform/server/internal/config"
	"github.com/ricardo/frp-panel-platform/server/internal/crypto"
	"github.com/ricardo/frp-panel-platform/server/internal/db"
)

type serviceCoverageFixture struct {
	app         *App
	database    *db.DB
	admin       AuthContext
	client      AuthContext
	adminLogin  LoginResult
	clientLogin LoginResult
	user        UserRecord
	password    string
}

func newServiceCoverageFixture(t *testing.T) serviceCoverageFixture {
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
	cfg := config.Config{
		DataDir:              root,
		Environment:          "development",
		AdminPassword:        "Admin-Password-2026!",
		SessionTTLHours:      12,
		PortStart:            6000,
		PortEnd:              6999,
		FRPSBindPort:         7000,
		FRPSPublicHost:       "frp.example.com",
		FRPSPublicPort:       7000,
		RouterSnapshotDir:    filepath.Join(root, "router"),
		FRPSTransportSecret:  "transport-secret-for-coverage",
		RouterControlTarget:  "http://127.0.0.1:7400",
		RouterBusinessTarget: "http://127.0.0.1:8080",
	}
	application := New(database, cfg, secrets)
	if _, err := application.EnsureAdmin(context.Background()); err != nil {
		t.Fatal(err)
	}
	adminLogin, err := application.Login(context.Background(), "admin", cfg.AdminPassword, "admin_panel", "127.0.0.1", "coverage")
	if err != nil {
		t.Fatal(err)
	}
	admin, err := application.Authenticate(context.Background(), adminLogin.Token)
	if err != nil {
		t.Fatal(err)
	}
	user, password, err := application.CreateUser(context.Background(), admin, "coverage-user")
	if err != nil {
		t.Fatal(err)
	}
	clientLogin, err := application.Login(context.Background(), user.Username, password, "client_panel", "127.0.0.1", "coverage-client")
	if err != nil {
		t.Fatal(err)
	}
	client, err := application.Authenticate(context.Background(), clientLogin.Token)
	if err != nil {
		t.Fatal(err)
	}
	return serviceCoverageFixture{app: application, database: database, admin: admin, client: client, adminLogin: adminLogin, clientLogin: clientLogin, user: user, password: password}
}

func TestServiceCoverageResourceLifecycle(t *testing.T) {
	fixture := newServiceCoverageFixture(t)
	ctx := context.Background()
	app, client, admin := fixture.app, fixture.client, fixture.admin

	if !ValidateCSRF(fixture.admin, "") {
		// Admin sessions created by the service fixture intentionally use a
		// browser CSRF hash; the empty token must fail closed.
	} else {
		t.Fatal("empty CSRF token was accepted")
	}
	if err := app.TouchSession(ctx, client); err != nil {
		t.Fatal(err)
	}
	if err := app.Heartbeat(ctx, client, "0.1.0", "0.68.0"); err != nil {
		t.Fatal(err)
	}

	tcpMapping, err := app.CreateMapping(ctx, client, MappingRequest{Name: "coverage-tcp", ProxyType: "tcp", LocalIP: "127.0.0.1", LocalPort: 8080}, "coverage-map-tcp-000001")
	if err != nil {
		t.Fatal(err)
	}
	if tcpMapping.RemotePort == nil || tcpMapping.LifecycleStatus != "pending_apply" {
		t.Fatalf("unexpected TCP mapping: %#v", tcpMapping)
	}
	if replay, err := app.CreateMapping(ctx, client, MappingRequest{Name: "coverage-tcp", ProxyType: "tcp", LocalIP: "127.0.0.1", LocalPort: 8080}, "coverage-map-tcp-000001"); err != nil || replay.ID != tcpMapping.ID {
		t.Fatalf("idempotent mapping replay failed: %#v %v", replay, err)
	}
	if _, err := app.CreateMapping(ctx, client, MappingRequest{Name: "different", ProxyType: "tcp", LocalIP: "127.0.0.1", LocalPort: 8081}, "coverage-map-tcp-000001"); !errors.Is(err, ErrIdempotencyReuse) {
		t.Fatalf("expected idempotency reuse error, got %v", err)
	}

	httpMapping, err := app.CreateMapping(ctx, client, MappingRequest{Name: "coverage-http", ProxyType: "http", LocalIP: "127.0.0.1", LocalPort: 8081}, "coverage-map-http-000001")
	if err != nil {
		t.Fatal(err)
	}
	domain, err := app.CreateDomain(ctx, client, DomainRequest{MappingID: httpMapping.ID, Hostname: "App.Example.com", HTTPSMode: "http_only", HTTPRedirect: true, DNSRecordType: "CNAME", DNSContent: "frp.example.com", DNSTTL: 300}, "coverage-domain-000001")
	if err != nil {
		t.Fatal(err)
	}
	if domain.Normalized != "app.example.com" || domain.Status != "pending_dns" {
		t.Fatalf("unexpected domain: %#v", domain)
	}
	if replay, err := app.CreateDomain(ctx, client, DomainRequest{MappingID: httpMapping.ID, Hostname: "App.Example.com", HTTPSMode: "http_only", HTTPRedirect: true, DNSRecordType: "CNAME", DNSContent: "frp.example.com", DNSTTL: 300}, "coverage-domain-000001"); err != nil || replay.ID != domain.ID {
		t.Fatalf("idempotent domain replay failed: %#v %v", replay, err)
	}

	if _, page, err := app.ListMappingsPage(ctx, client.UserID, 1, 1); err != nil || page.Total != 2 || page.PageSize != 1 {
		t.Fatalf("mapping pagination failed: %#v %v", page, err)
	}
	if _, page, err := app.ListDomainsPage(ctx, client.UserID, 1, 50); err != nil || page.Total != 1 {
		t.Fatalf("domain pagination failed: %#v %v", page, err)
	}
	dashboard, err := app.Dashboard(ctx, client)
	if err != nil || dashboard.Counts.TotalMappings != 2 || dashboard.FRPCredential.Status != "active" {
		t.Fatalf("dashboard failed: %#v %v", dashboard, err)
	}
	snapshot, err := app.FullConfig(ctx, client)
	if err != nil || snapshot.Signature == "" || snapshot.ConfigHash == "" || snapshot.UserID != client.UserID {
		t.Fatalf("full config failed: %#v %v", snapshot, err)
	}
	if err := app.ApplyResult(ctx, client, ApplyResultRequest{Status: "succeeded", ConfigVersion: snapshot.ConfigVersion, AppliedConfigHash: snapshot.ConfigHash, ClientPanelVersion: "0.1.0", FRPCVersion: "0.68.0"}); err != nil {
		t.Fatal(err)
	}
	if routerSnapshot, err := app.BuildRouterSnapshot(ctx); err != nil || routerSnapshot.Version < 1 || routerSnapshot.HMAC == "" {
		t.Fatalf("router snapshot build failed: %#v %v", routerSnapshot, err)
	}
	if status, err := app.RouterStatus(ctx); err != nil || status.Adapter != "file-last-good" || status.LastGoodVersion == nil {
		t.Fatalf("router status failed: %#v %v", status, err)
	}
	if certificates, err := app.RouterCertificates(ctx); err != nil || len(certificates) != 0 {
		t.Fatalf("empty router certificate set failed: %#v %v", certificates, err)
	}

	if err := app.ToggleMapping(ctx, client, tcpMapping.ID, false, ToggleMappingOptions{IdempotencyKey: "coverage-toggle-000001"}); err != nil {
		t.Fatal(err)
	}
	if err := app.ToggleMapping(ctx, client, tcpMapping.ID, true, ToggleMappingOptions{IdempotencyKey: "coverage-toggle-000002"}); err != nil {
		t.Fatal(err)
	}
	updated, err := app.UpdateMapping(ctx, client, tcpMapping.ID, MappingRequest{Name: "coverage-tcp-updated", ProxyType: "tcp", LocalIP: "127.0.0.1", LocalPort: 8082, RemotePort: tcpMapping.RemotePort}, "coverage-update-000001")
	if err != nil || updated.Revision != tcpMapping.Revision+1 {
		t.Fatalf("mapping update failed: %#v %v", updated, err)
	}

	if ok, _, _ := app.AuthorizeFRPWithCredentials(ctx, "Login", fixture.clientLogin.FRPUsername, fixture.clientLogin.RuntimeCredential, fixture.clientLogin.FRPSecret, client.Generation, "", 0, 0, "", ""); !ok {
		t.Fatal("valid FRP Login was denied")
	}
	if ok, code, _ := app.AuthorizeFRPWithCredentials(ctx, "NewProxy", fixture.clientLogin.FRPUsername, fixture.clientLogin.RuntimeCredential, fixture.clientLogin.FRPSecret, client.Generation, httpMapping.ID, httpMapping.Revision, 0, domain.Normalized, "http"); !ok || code != "" {
		t.Fatalf("valid HTTP FRP proxy was denied: ok=%v code=%q", ok, code)
	}
	if ok, code, _ := app.AuthorizeFRPWithCredentials(ctx, "NewProxy", fixture.clientLogin.FRPUsername, fixture.clientLogin.RuntimeCredential, "wrong-secret", client.Generation, httpMapping.ID, httpMapping.Revision, 0, domain.Normalized, "http"); ok || code != "FRP_USER_CREDENTIAL_INVALID" {
		t.Fatalf("invalid FRP user credential was accepted: ok=%v code=%q", ok, code)
	}

	if err := app.ResolveDomainDNS(ctx, client, domain.ID, "adopt", "coverage-dns-action-000001"); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DeleteDomain(ctx, client, domain.ID, "coverage-domain-delete-000001"); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DeleteMapping(ctx, client, tcpMapping.ID, false, "coverage-mapping-delete-000001"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := app.OperationsPage(ctx, client.UserID, false, 1, 50); err != nil {
		t.Fatal(err)
	}

	if _, err := app.CloudflareStatus(ctx, client.UserID); err != nil {
		t.Fatal(err)
	}
	reauthTicket, _, err := app.IssueReauthTicket(ctx, admin, fixture.app.Config.AdminPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.RequireReauthTicket(ctx, admin, reauthTicket); err != nil {
		t.Fatal(err)
	}
	if err := app.SaveCloudflareToken(ctx, admin, "coverage-cloudflare-token-0123456789", reauthTicket); err != nil {
		t.Fatal(err)
	}
	if status, err := app.CloudflareStatus(ctx, admin.UserID); err != nil || status["configured"] != true {
		t.Fatalf("Cloudflare token status did not become configured: %#v %v", status, err)
	}
	if err := app.ClearCloudflareToken(ctx, admin, fixture.app.Config.AdminPassword); err != nil {
		t.Fatal(err)
	}

	if _, page, err := app.AdminUsersPage(ctx, 1, 50); err != nil || page.Total < 2 {
		t.Fatalf("admin user pagination failed: %#v %v", page, err)
	}
	if err := app.SetUserStatus(ctx, admin, fixture.user.ID, "disabled"); err != nil {
		t.Fatal(err)
	}
	if err := app.SetUserStatus(ctx, admin, fixture.user.ID, "active"); err != nil {
		t.Fatal(err)
	}
	if _, err := app.ResetUserPassword(ctx, admin, fixture.user.ID); err != nil {
		t.Fatal(err)
	}
	adminResetTicket, _, err := app.IssueReauthTicket(ctx, admin, fixture.app.Config.AdminPassword)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := app.ResetFRPCredential(ctx, admin, fixture.user.ID, adminResetTicket, "coverage-frp-reset-000001"); err != nil || result.SecretVersion < 2 {
		t.Fatalf("admin FRP reset failed: %#v %v", result, err)
	}
	if result, err := app.ResetFRPCredential(ctx, admin, fixture.user.ID, adminResetTicket, "coverage-frp-reset-000001"); err != nil || result.SecretVersion < 2 {
		t.Fatalf("admin FRP reset idempotent replay failed: %#v %v", result, err)
	}
	if err := app.TouchSession(ctx, client); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("revoked client session remained touchable: %v", err)
	}

	var operationID string
	if err := app.DB.QueryRowContext(ctx, `SELECT id FROM operations WHERE resource_type='domain' AND resource_id=? AND operation_type='create' ORDER BY created_at LIMIT 1`, domain.ID).Scan(&operationID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.ExecContext(ctx, `UPDATE operations SET status='failed',phase='dns',error_code='TEST',error_message='coverage' WHERE id=?`, operationID); err != nil {
		t.Fatal(err)
	}
	if err := app.RetryOperation(ctx, admin, operationID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := app.OperationsPage(ctx, "", true, 1, 200); err != nil {
		t.Fatal(err)
	}

	if err := app.Logout(ctx, admin, "coverage"); err != nil {
		t.Fatal(err)
	}
	if err := app.Logout(ctx, client, "coverage"); err != nil {
		t.Fatal(err)
	}
}

func TestServiceCoverageInvalidInputsAndDeleteWorkflow(t *testing.T) {
	fixture := newServiceCoverageFixture(t)
	ctx := context.Background()
	app, client, admin := fixture.app, fixture.client, fixture.admin

	if _, err := app.CreateMapping(ctx, client, MappingRequest{Name: "invalid", ProxyType: "bad", LocalIP: "127.0.0.1", LocalPort: 1}, "coverage-invalid-map"); err == nil {
		t.Fatal("invalid mapping was accepted")
	}
	if _, err := app.CreateDomain(ctx, client, DomainRequest{MappingID: "missing", Hostname: "bad.example.com", HTTPSMode: "http_only"}, "coverage-invalid-domain"); err == nil {
		t.Fatal("domain without HTTP mapping was accepted")
	}
	if err := app.RetryOperation(ctx, client, "missing-operation"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing operation error=%v", err)
	}
	if _, err := app.DeleteUser(ctx, client, fixture.user.ID, false, "coverage-user-delete-forbidden"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("non-admin user deletion error=%v", err)
	}

	mapping, err := app.CreateMapping(ctx, client, MappingRequest{Name: "delete-me", ProxyType: "tcp", LocalIP: "127.0.0.1", LocalPort: 8090}, "coverage-delete-map")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.DeleteUser(ctx, admin, fixture.user.ID, true, "coverage-user-delete-000001"); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DeleteUser(ctx, admin, fixture.user.ID, true, "coverage-user-delete-000002"); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := app.DB.QueryRowContext(ctx, `SELECT status FROM users WHERE id=?`, fixture.user.ID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "deleting" {
		t.Fatalf("user delete did not enter deleting state: %s", status)
	}
	if _, _, err := app.ListMappingsPage(ctx, fixture.user.ID, 0, 1000); err != nil {
		t.Fatal(err)
	}
	_ = mapping

	if _, err := app.Authenticate(ctx, "Bearer "+fixture.clientLogin.Token); err == nil {
		t.Fatal("deleted user's session remained valid")
	}
	if _, err := app.DB.ExecContext(ctx, `UPDATE operations SET status='failed',compensation_status='external_residue' WHERE resource_type='user' AND resource_id=?`, fixture.user.ID); err != nil {
		t.Fatal(err)
	}
	var operationID string
	if err := app.DB.QueryRowContext(ctx, `SELECT id FROM operations WHERE resource_type='user' AND resource_id=? ORDER BY created_at DESC LIMIT 1`, fixture.user.ID).Scan(&operationID); err != nil {
		t.Fatal(err)
	}
	if err := app.RetryOperation(ctx, admin, operationID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.CloudflareStatus(ctx, fixture.user.ID); err != nil && !errors.Is(err, sql.ErrNoRows) {
		t.Fatal(err)
	}
}
