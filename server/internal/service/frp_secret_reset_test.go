package service

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/ricardo/frp-panel-platform/server/internal/config"
	"github.com/ricardo/frp-panel-platform/server/internal/crypto"
	"github.com/ricardo/frp-panel-platform/server/internal/db"
)

func TestAdminFRPCredentialResetRevokesRuntimeAndIsIdempotent(t *testing.T) {
	app, database, admin, user := newUserDeletionFixture(t)
	ctx := context.Background()
	var beforeDesired, beforeGeneration int64
	if err := database.QueryRow(`SELECT desired_config_version,active_session_generation FROM users WHERE id=?`, user.UserID).Scan(&beforeDesired, &beforeGeneration); err != nil {
		t.Fatal(err)
	}

	first, err := app.ResetFRPCredential(ctx, admin, user.UserID, "Admin-Password-2026!", "frp-reset-admin-123456")
	if err != nil {
		t.Fatal(err)
	}
	replay, err := app.ResetFRPCredential(ctx, admin, user.UserID, "Admin-Password-2026!", "frp-reset-admin-123456")
	if err != nil {
		t.Fatal(err)
	}
	if first != replay || first.Status != "rotated" || first.SecretVersion != 2 {
		t.Fatalf("FRP reset was not an idempotent versioned rotation: first=%#v replay=%#v", first, replay)
	}

	var desired, generation, secretVersion int64
	if err := database.QueryRow(`SELECT u.desired_config_version,u.active_session_generation,fc.secret_version FROM users u JOIN frp_credentials fc ON fc.user_id=u.id WHERE u.id=?`, user.UserID).Scan(&desired, &generation, &secretVersion); err != nil {
		t.Fatal(err)
	}
	if desired != beforeDesired+1 || generation != beforeGeneration+1 || generation != first.SessionGeneration || secretVersion != first.SecretVersion {
		t.Fatalf("rotation versions were not advanced exactly once: desired=%d generation=%d secret_version=%d result=%#v before=(%d,%d)", desired, generation, secretVersion, first, beforeDesired, beforeGeneration)
	}
	var revokedSessions, revokedRuntime int
	if err := database.QueryRow(`SELECT COUNT(1) FROM sessions WHERE user_id=? AND revoke_reason='FRP_SECRET_RESET'`, user.UserID).Scan(&revokedSessions); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT COUNT(1) FROM frp_runtime_credentials WHERE user_id=? AND revoked_at IS NOT NULL`, user.UserID).Scan(&revokedRuntime); err != nil {
		t.Fatal(err)
	}
	if revokedSessions == 0 || revokedRuntime == 0 {
		t.Fatalf("FRP reset did not revoke active credentials: sessions=%d runtime=%d", revokedSessions, revokedRuntime)
	}
	var observedStatus string
	if err := database.QueryRow(`SELECT observed_client_status FROM user_runtime_state WHERE user_id=?`, user.UserID).Scan(&observedStatus); err != nil {
		t.Fatal(err)
	}
	if observedStatus != "offline" {
		t.Fatalf("runtime state remained online after FRP reset: %q", observedStatus)
	}
	var auditCount int
	if err := database.QueryRow(`SELECT COUNT(1) FROM audit_logs WHERE action='frp_secret_reset' AND resource_id=?`, user.UserID).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("FRP reset audit was duplicated or missing: %d", auditCount)
	}
}

func newFRPSelfResetFixture(t *testing.T) (*App, AuthContext, string) {
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
	_, password, err := app.CreateUser(context.Background(), admin, "self-reset")
	if err != nil {
		t.Fatal(err)
	}
	clientLogin, err := app.Login(context.Background(), "self-reset", password, "client_panel", "127.0.0.1", "test")
	if err != nil {
		t.Fatal(err)
	}
	user, err := app.Authenticate(context.Background(), clientLogin.Token)
	if err != nil {
		t.Fatal(err)
	}
	return app, user, password
}

func TestUserCanSelfResetFRPCredentialAfterPasswordReauthentication(t *testing.T) {
	app, user, password := newFRPSelfResetFixture(t)
	if _, err := app.ResetFRPCredential(context.Background(), user, "", "wrong-password", "frp-reset-self-negative"); err != ErrInvalidCredentials {
		t.Fatalf("wrong self-reset password was not rejected: %v", err)
	}
	result, err := app.ResetFRPCredential(context.Background(), user, "", password, "frp-reset-self-123456")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "rotated" || result.SecretVersion != 2 {
		t.Fatalf("self reset did not rotate the secret version: %#v", result)
	}
}
