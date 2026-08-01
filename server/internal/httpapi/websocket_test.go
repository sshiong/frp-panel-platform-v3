package httpapi

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/ricardo/frp-panel-platform/server/internal/config"
	"github.com/ricardo/frp-panel-platform/server/internal/crypto"
	"github.com/ricardo/frp-panel-platform/server/internal/db"
	"github.com/ricardo/frp-panel-platform/server/internal/service"
)

func TestWebSocketHeartbeatAndUserDisable(t *testing.T) {
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
	cfg := config.Config{DataDir: root, Environment: "development", AdminPassword: "Admin-Password-2026!", SessionTTLHours: 12, AllowedOrigins: []string{"http://127.0.0.1:7410"}, PortStart: 6000, PortEnd: 6999}
	app := service.New(database, cfg, secrets)
	if _, err := app.EnsureAdmin(context.Background()); err != nil {
		t.Fatal(err)
	}
	adminLogin, err := app.Login(context.Background(), "admin", cfg.AdminPassword, "admin_panel", "127.0.0.1", "test")
	if err != nil {
		t.Fatal(err)
	}
	admin, err := app.Authenticate(context.Background(), adminLogin.Token)
	if err != nil {
		t.Fatal(err)
	}
	_, initialPassword, err := app.CreateUser(context.Background(), admin, "alice")
	if err != nil {
		t.Fatal(err)
	}
	clientLogin, err := app.Login(context.Background(), "alice", initialPassword, "client_panel", "127.0.0.1", "test")
	if err != nil {
		t.Fatal(err)
	}
	api := New(app, slog.New(slog.NewTextHandler(io.Discard, nil)))
	server := httptest.NewServer(api.Handler())
	defer server.Close()
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/api/v1/ws"
	dialer := websocket.Dialer{HandshakeTimeout: 5 * time.Second}
	_, incompatibleResponse, incompatibleErr := dialer.Dial(wsURL, http.Header{
		"Authorization":          []string{"Bearer " + clientLogin.Token},
		"Origin":                 []string{"http://127.0.0.1:7410"},
		"X-FRP-Protocol-Version": []string{"v0"},
	})
	if incompatibleErr == nil || incompatibleResponse == nil || incompatibleResponse.StatusCode != http.StatusUpgradeRequired {
		t.Fatalf("unsupported WebSocket protocol must return 426: response=%v err=%v", incompatibleResponse, incompatibleErr)
	}
	conn, response, err := dialer.Dial(wsURL, http.Header{"Authorization": []string{"Bearer " + clientLogin.Token}, "Origin": []string{"http://127.0.0.1:7410"}})
	if err != nil {
		if response != nil {
			t.Fatalf("websocket dial failed with status %d: %v", response.StatusCode, err)
		}
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var connected wsEnvelope
	if err := conn.ReadJSON(&connected); err != nil || connected.Type != "connected" {
		t.Fatalf("connected envelope: %#v %v", connected, err)
	}
	if err := conn.WriteJSON(wsEnvelope{ProtocolVersion: "v1", Type: "heartbeat", Payload: map[string]string{"client": "test"}}); err != nil {
		t.Fatal(err)
	}
	var heartbeat wsEnvelope
	if err := conn.ReadJSON(&heartbeat); err != nil || heartbeat.Type != "heartbeat_ack" {
		t.Fatalf("heartbeat envelope: %#v %v", heartbeat, err)
	}
	api.notifyUser(clientLogin.User.ID, "user_disabled", map[string]string{"reason": "test"})
	var disabled wsEnvelope
	if err := conn.ReadJSON(&disabled); err != nil || disabled.Type != "user_disabled" {
		t.Fatalf("disable envelope: %#v %v", disabled, err)
	}
}
