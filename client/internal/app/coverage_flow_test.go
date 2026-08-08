package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ricardo/frp-panel-platform/client/internal/config"
	"github.com/ricardo/frp-panel-platform/client/internal/supervisor"
	"github.com/ricardo/frp-panel-platform/client/internal/version"
)

func TestAppCoverageLifecycleAndProxy(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := supervisor.Snapshot{
		SchemaVersion:     "v1",
		ConfigVersion:     1,
		UserID:            "coverage-user",
		SessionGeneration: 1,
		IssuedAt:          time.Now().UTC().Format(time.RFC3339Nano),
		ExpiresAt:         time.Now().UTC().Add(5 * time.Minute).Format(time.RFC3339Nano),
		ConfigHash:        "coverage-hash",
		SigningKeyID:      "coverage-key",
		Payload: map[string]interface{}{
			"frps_public_host": "frp.example.com",
			"frps_public_port": 7000,
			"mappings":         []interface{}{},
		},
	}
	unsigned := snapshot
	unsigned.Signature = ""
	encoded, err := json.Marshal(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, encoded))
	var applyCount atomic.Int32
	var logoutCount atomic.Int32
	var clientVersionHeader atomic.Value
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/compatibility" || r.URL.Path == "/api/v1/auth/client-login" {
			clientVersionHeader.Store(r.Header.Get("X-FRP-Client-Version"))
		}
		switch r.URL.Path {
		case "/api/v1/auth/client-login":
			_, _ = io.WriteString(w, `{"token":"server-token","session_expires_at":"2030-01-01T00:00:00Z","runtime_credential":"runtime-token","frp_username":"coverage-user","frp_secret":"user-secret","frps_transport_secret":"transport-secret","user":{"id":"coverage-user","username":"coverage-user","role":"user","status":"active","must_change_password":false,"must_change_username":false}}`)
		case "/api/v1/auth/logout":
			logoutCount.Add(1)
			_, _ = io.WriteString(w, `{"ok":true}`)
		case "/api/v1/config/full":
			_ = json.NewEncoder(w).Encode(snapshot)
		case "/api/v1/config/signing-key":
			_ = json.NewEncoder(w).Encode(map[string]string{"public_key": hex.EncodeToString(publicKey)})
		case "/api/v1/config/apply-result":
			applyCount.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		case "/api/v1/dashboard":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "online", "config_version": snapshot.ConfigVersion})
		case "/api/v1/auth/reauth":
			_ = json.NewEncoder(w).Encode(map[string]string{"reauth_ticket": "ticket", "expires_at": "2030-01-01T00:00:00Z"})
		case "/api/v1/ws":
			w.WriteHeader(http.StatusUpgradeRequired)
		case "/error":
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{"code": "CONFIG_VERSION_CONFLICT", "detail": "retry"})
		case "/bad-json":
			_, _ = io.WriteString(w, "{")
		default:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"items": []interface{}{}, "ok": true})
		}
	})
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.Listener = listener
	server.Start()
	defer server.Close()

	client := New(config.Config{DataDir: t.TempDir(), Environment: "development", FRPCVersion: "0.68.0", ListenAddr: "127.0.0.1:7410"})
	if _, err := client.Login(context.Background(), server.URL, "coverage-user", "Coverage-Password-2026!"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		client.stopWebSocket()
		_ = client.Supervisor.Stop(context.Background())
		_ = client.Supervisor.ClearRuntimeSecrets()
	})
	if applyCount.Load() != 1 || client.SupervisorStatus().AppliedVersion != snapshot.ConfigVersion {
		t.Fatalf("initial configuration was not applied: count=%d status=%#v", applyCount.Load(), client.SupervisorStatus())
	}
	if got := clientVersionHeader.Load(); got != version.ClientVersion {
		t.Fatalf("Client Panel version header=%v, want %q", got, version.ClientVersion)
	}
	if !client.ValidateLocal(client.SessionCookie()) || client.SessionCookie() == "" || !client.CSRFValid(client.Session().CSRFToken) {
		t.Fatal("local client session helpers rejected the active session")
	}
	if client.ValidateLocal("wrong-cookie") || client.CSRFValid("wrong-csrf") {
		t.Fatal("local session helpers accepted invalid credentials")
	}

	var dashboard map[string]interface{}
	if err := client.Proxy(context.Background(), http.MethodGet, "/api/v1/dashboard", nil, "", &dashboard); err != nil || dashboard["status"] != "online" {
		t.Fatalf("dashboard proxy failed: %#v %v", dashboard, err)
	}
	if err := client.Proxy(context.Background(), http.MethodPost, "/api/v1/auth/reauth", map[string]string{"current_password": "x"}, "wrong-csrf", &map[string]interface{}{}); err == nil {
		t.Fatal("invalid local CSRF token was accepted by Proxy")
	}
	var reauth map[string]interface{}
	if err := client.Proxy(context.Background(), http.MethodPost, "/api/v1/auth/reauth", map[string]string{"current_password": "x"}, client.Session().CSRFToken, &reauth); err != nil || reauth["reauth_ticket"] != "ticket" {
		t.Fatalf("reauth proxy failed: %#v %v", reauth, err)
	}
	if err := client.FetchConfigAndApply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if applyCount.Load() != 2 {
		t.Fatalf("config synchronization count=%d, want 2", applyCount.Load())
	}

	secondServer := httptest.NewServer(handler)
	if _, err := client.Login(context.Background(), secondServer.URL, "coverage-user", "Coverage-Password-2026!"); err != nil {
		t.Fatal(err)
	}
	if logoutCount.Load() != 1 {
		t.Fatalf("switching Server Panels did not best-effort logout old session: count=%d", logoutCount.Load())
	}
	var switchedDashboard map[string]interface{}
	if err := client.Proxy(context.Background(), http.MethodGet, "/api/v1/dashboard", nil, "", &switchedDashboard); err != nil {
		t.Fatal(err)
	}
	secondServer.Close()
	var cachedAfterDisconnect map[string]interface{}
	if err := client.Proxy(context.Background(), http.MethodGet, "/api/v1/dashboard", nil, "", &cachedAfterDisconnect); err != nil || cachedAfterDisconnect["status"] != "online" || client.ServerReachable() {
		t.Fatalf("valid local session did not provide cached read-only dashboard after disconnect: %#v err=%v reachable=%v", cachedAfterDisconnect, err, client.ServerReachable())
	}

	var remoteResponse map[string]interface{}
	if err := client.serverRequest(context.Background(), server.URL, http.MethodGet, "/error", nil, "token", &remoteResponse); err == nil {
		t.Fatal("remote problem response was accepted")
	} else {
		var remote RemoteError
		if !errors.As(err, &remote) || remote.Status != http.StatusConflict || remote.Code != "CONFIG_VERSION_CONFLICT" {
			t.Fatalf("unexpected remote problem: %T %v", err, err)
		}
	}
	if err := client.serverRequest(context.Background(), server.URL, http.MethodGet, "/bad-json", "", "token", &remoteResponse); err == nil {
		t.Fatal("malformed JSON response was accepted")
	}

	if err := client.Logout(context.Background()); err != nil {
		t.Fatal(err)
	}
	if logoutCount.Load() != 1 || client.ValidateLocal(client.SessionCookie()) || client.SessionCookie() != "" {
		t.Fatalf("logout did not clear local session: count=%d cookie=%q", logoutCount.Load(), client.SessionCookie())
	}
	if err := client.Proxy(context.Background(), http.MethodPost, "/api/v1/auth/reauth", nil, "", &remoteResponse); err == nil {
		t.Fatal("offline write was accepted")
	}
	var cached map[string]interface{}
	if err := client.Proxy(context.Background(), http.MethodGet, "/api/v1/dashboard", nil, "", &cached); err == nil {
		t.Fatal("logged-out client exposed cached dashboard")
	}
}
