package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/ricardo/frp-panel-platform/client/internal/config"
)

func TestWebsocketURL(t *testing.T) {
	got, err := websocketURL("https://panel.example.test/control/")
	if err != nil {
		t.Fatal(err)
	}
	if got != "wss://panel.example.test/control/api/v1/ws" {
		t.Fatalf("unexpected secure WebSocket URL: %s", got)
	}
	got, err = websocketURL("http://127.0.0.1:7400")
	if err != nil {
		t.Fatal(err)
	}
	if got != "ws://127.0.0.1:7400/api/v1/ws" {
		t.Fatalf("unexpected local WebSocket URL: %s", got)
	}
}

func TestWebsocketConnectionStopsOnRemoteDisable(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.WriteJSON(wsEnvelope{ProtocolVersion: "v1", Type: "user_disabled"})
		_, _, _ = conn.ReadMessage()
	}))
	defer server.Close()

	conn, _, err := dialServerWebSocket(context.Background(), server.URL, "opaque-token", "http://127.0.0.1:7410")
	if err != nil {
		t.Fatal(err)
	}
	client := New(config.Config{DataDir: t.TempDir()})
	client.wsMu.Lock()
	client.wsGeneration = 1
	client.wsCancel = func() {}
	client.wsMu.Unlock()
	if !client.runWebSocketConnection(context.Background(), conn, 1) {
		t.Fatal("remote disable event did not invalidate the connection")
	}
	if _, token := client.serverCredentials(); token != "" {
		t.Fatal("remote disable did not clear the session")
	}
}
