package service

import (
	"context"
	"database/sql"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ricardo/frp-panel-platform/server/internal/config"
	"github.com/ricardo/frp-panel-platform/server/internal/crypto"
	"github.com/ricardo/frp-panel-platform/server/internal/db"
)

func TestGeneratedAdminMustCompleteUsernameAndPasswordChange(t *testing.T) {
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
	app := New(database, config.Config{DataDir: root, Environment: "development", SessionTTLHours: 12}, secrets)
	initialPassword, err := app.EnsureAdmin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if initialPassword == "" {
		t.Fatal("generated initial admin password was not returned")
	}

	login, err := app.Login(context.Background(), "admin", initialPassword, "admin_panel", "192.0.2.10", "acceptance-test")
	if err != nil {
		t.Fatal(err)
	}
	if !login.User.MustChangePassword || !login.User.MustChangeUsername {
		t.Fatalf("generated admin did not require both credential changes: %#v", login.User)
	}
	authContext, err := app.Authenticate(context.Background(), login.Token)
	if err != nil {
		t.Fatal(err)
	}
	if !authContext.MustChange || !authContext.MustChangeUsername {
		t.Fatalf("session did not carry both initial-credential gates: %#v", authContext)
	}
	if err := app.ChangeCredentials(context.Background(), authContext, initialPassword, "control-admin", "Control-Password-2026!"); err != nil {
		t.Fatal(err)
	}

	if _, err := app.Login(context.Background(), "admin", "Control-Password-2026!", "admin_panel", "192.0.2.10", "acceptance-test"); err == nil {
		t.Fatal("old initial administrator username remained usable")
	}
	updated, err := app.Login(context.Background(), "control-admin", "Control-Password-2026!", "admin_panel", "192.0.2.10", "acceptance-test")
	if err != nil {
		t.Fatal(err)
	}
	if updated.User.MustChangePassword || updated.User.MustChangeUsername {
		t.Fatalf("credential gates remained set after initial completion: %#v", updated.User)
	}
}

func TestAuditRetainsRequestBoundaryMetadataAndSanitizesUserAgent(t *testing.T) {
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
	app := New(database, config.Config{DataDir: root, Environment: "development", AdminPassword: "Admin-Password-2026!", SessionTTLHours: 12}, secrets)
	if _, err := app.EnsureAdmin(context.Background()); err != nil {
		t.Fatal(err)
	}
	login, err := app.Login(context.Background(), "admin", "Admin-Password-2026!", "admin_panel", "198.51.100.4", "browser")
	if err != nil {
		t.Fatal(err)
	}
	authContext, err := app.Authenticate(context.Background(), login.Token)
	if err != nil {
		t.Fatal(err)
	}
	requestContext := WithRequestMetadata(context.Background(), "203.0.113.7", "acceptance-agent\ninjected", "request-acceptance-001")
	if err := app.Audit(requestContext, authContext, "acceptance_probe", "system", "audit", "success", map[string]interface{}{"status": "ok"}, "operation-acceptance-001"); err != nil {
		t.Fatal(err)
	}
	var sourceIP, userAgent, requestID, sessionID string
	var generation int64
	if err := database.QueryRow(`SELECT source_ip,user_agent,request_id,server_session_id,session_generation FROM audit_logs WHERE action='acceptance_probe'`).Scan(&sourceIP, &userAgent, &requestID, &sessionID, &generation); err != nil {
		t.Fatal(err)
	}
	if sourceIP != "203.0.113.7" || userAgent != "acceptance-agent injected" || requestID != "request-acceptance-001" {
		t.Fatalf("audit request metadata mismatch: ip=%q ua=%q request=%q", sourceIP, userAgent, requestID)
	}
	if sessionID != authContext.SessionID || generation != authContext.Generation {
		t.Fatalf("audit session metadata mismatch: session=%q/%q generation=%d/%d", sessionID, authContext.SessionID, generation, authContext.Generation)
	}
	var operationID string
	if err := database.QueryRow(`SELECT operation_id FROM audit_logs WHERE action='acceptance_probe'`).Scan(&operationID); err != nil {
		t.Fatal(err)
	}
	if operationID != "operation-acceptance-001" {
		t.Fatalf("audit operation id=%q", operationID)
	}
	var missing string
	if err := database.QueryRow(`SELECT request_id FROM audit_logs WHERE action='missing'`).Scan(&missing); err != sql.ErrNoRows {
		t.Fatalf("unexpected unrelated audit row: %v", err)
	}
}

func TestSessionReplacementInvalidatesOldHTTPAndFRPWithinBound(t *testing.T) {
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
	app := New(database, config.Config{DataDir: root, Environment: "development", AdminPassword: "Admin-Password-2026!", SessionTTLHours: 12, PortStart: 6000, PortEnd: 6999}, secrets)
	if _, err := app.EnsureAdmin(context.Background()); err != nil {
		t.Fatal(err)
	}
	adminLogin, err := app.Login(context.Background(), "admin", "Admin-Password-2026!", "admin_panel", "127.0.0.1", "acceptance")
	if err != nil {
		t.Fatal(err)
	}
	admin, err := app.Authenticate(context.Background(), adminLogin.Token)
	if err != nil {
		t.Fatal(err)
	}
	_, initialPassword, err := app.CreateUser(context.Background(), admin, "replacement-user")
	if err != nil {
		t.Fatal(err)
	}
	first, err := app.Login(context.Background(), "replacement-user", initialPassword, "client_panel", "127.0.0.1", "acceptance")
	if err != nil {
		t.Fatal(err)
	}
	oldContext, err := app.Authenticate(context.Background(), first.Token)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.ChangePassword(context.Background(), oldContext, initialPassword, "Replacement-Password-2026!"); err != nil {
		t.Fatal(err)
	}
	mapping, err := app.CreateMapping(context.Background(), oldContext, MappingRequest{Name: "replacement", ProxyType: "tcp", LocalIP: "127.0.0.1", LocalPort: 8080}, "replacement-mapping-123456")
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	second, err := app.Login(context.Background(), "replacement-user", "Replacement-Password-2026!", "client_panel", "127.0.0.1", "acceptance")
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(started) > 5*time.Second {
		t.Fatal("session replacement exceeded PERF-007 HTTP invalidation bound")
	}
	if _, err := app.Authenticate(context.Background(), first.Token); err == nil {
		t.Fatal("old HTTP session remained valid after replacement")
	}
	allowed, code, _ := app.AuthorizeFRPWithCredentials(context.Background(), "NewWorkConn", first.FRPUsername, first.RuntimeCredential, first.FRPSecret, oldContext.Generation, mapping.ID, mapping.Revision, 0, "", "tcp")
	if allowed || code != "FRP_RUNTIME_CREDENTIAL_INVALID" {
		t.Fatalf("old FRP runtime credential remained usable: allowed=%v code=%q", allowed, code)
	}
	if _, err := app.Authenticate(context.Background(), second.Token); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentClientLoginLeavesOneActiveSession(t *testing.T) {
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
	app := New(database, config.Config{DataDir: root, Environment: "development", AdminPassword: "Admin-Password-2026!", SessionTTLHours: 12}, secrets)
	if _, err := app.EnsureAdmin(context.Background()); err != nil {
		t.Fatal(err)
	}
	admin, err := app.Login(context.Background(), "admin", "Admin-Password-2026!", "admin_panel", "127.0.0.1", "acceptance")
	if err != nil {
		t.Fatal(err)
	}
	_, initialPassword, err := app.CreateUser(context.Background(), AuthContext{UserID: admin.User.ID, Role: "admin", SessionID: admin.SessionID, Generation: 1}, "concurrent-user")
	if err != nil {
		t.Fatal(err)
	}
	first, err := app.Login(context.Background(), "concurrent-user", initialPassword, "client_panel", "127.0.0.1", "acceptance")
	if err != nil {
		t.Fatal(err)
	}
	firstContext, err := app.Authenticate(context.Background(), first.Token)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.ChangePassword(context.Background(), firstContext, initialPassword, "Concurrent-Password-2026!"); err != nil {
		t.Fatal(err)
	}

	const attempts = 8
	start := make(chan struct{})
	results := make(chan LoginResult, attempts)
	errorsCh := make(chan error, attempts)
	var waitGroup sync.WaitGroup
	for index := 0; index < attempts; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			result, loginErr := app.Login(context.Background(), "concurrent-user", "Concurrent-Password-2026!", "client_panel", "127.0.0.1", "concurrent-acceptance")
			if loginErr != nil {
				errorsCh <- loginErr
				return
			}
			results <- result
		}()
	}
	close(start)
	waitGroup.Wait()
	close(results)
	close(errorsCh)
	for loginErr := range errorsCh {
		t.Fatal(loginErr)
	}
	if len(results) != attempts {
		t.Fatalf("concurrent login successes=%d, want %d", len(results), attempts)
	}
	var active int
	if err := database.QueryRow(`SELECT COUNT(1) FROM sessions WHERE user_id=? AND login_channel='client_panel' AND revoked_at IS NULL`, first.User.ID).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 1 {
		t.Fatalf("concurrent client login left %d active sessions, want 1", active)
	}
}
