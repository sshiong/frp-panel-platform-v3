package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ricardo/frp-panel-platform/client/internal/config"
)

func TestAppCoverageLocalSessionWebSocketAndURLHelpers(t *testing.T) {
	client := New(config.Config{ListenAddr: "0.0.0.0:7410"})
	if (RemoteError{Code: "CODE"}).Error() != "CODE" || (RemoteError{Detail: "detail", Code: "CODE"}).Error() != "detail" {
		t.Fatal("RemoteError string formatting is incorrect")
	}
	for _, value := range []string{"", "ftp://example.com", "://broken"} {
		if _, err := websocketURL(value); err == nil {
			t.Fatalf("invalid WebSocket URL was accepted: %q", value)
		}
	}
	if got, err := websocketURL("http://example.com/panel/"); err != nil || got != "ws://example.com/panel/api/v1/ws" {
		t.Fatalf("http WebSocket URL=%q err=%v", got, err)
	}
	if got, err := websocketURL("https://example.com"); err != nil || got != "wss://example.com/api/v1/ws" {
		t.Fatalf("https WebSocket URL=%q err=%v", got, err)
	}
	if localOrigin(client.Config) != "https://127.0.0.1:7410" {
		// The client is HTTP by default; this assertion is replaced below with
		// the explicit TLS configuration that selects the HTTPS Origin.
		if got := localOrigin(client.Config); got != "http://127.0.0.1:7410" {
			t.Fatalf("local origin=%q", got)
		}
	}
	tlsOrigin := client.Config
	tlsOrigin.TLSCertFile = "/tmp/client-cert.pem"
	tlsOrigin.TLSKeyFile = "/tmp/client-key.pem"
	if got := localOrigin(tlsOrigin); got != "https://127.0.0.1:7410" {
		t.Fatalf("TLS local origin=%q", got)
	}
	if jitter(0) <= 0 || jitter(time.Millisecond) <= 0 {
		t.Fatal("jitter returned a non-positive delay")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if waitWebSocket(ctx, time.Millisecond) {
		t.Fatal("canceled WebSocket wait returned true")
	}

	client.mu.Lock()
	client.localSession = "local"
	client.csrfToken = "csrf"
	client.expiresAt = time.Now().UTC().Add(time.Minute)
	client.mu.Unlock()
	if !client.ValidateLocal("local") || !client.CSRFValid("csrf") || client.ValidateLocal("bad") || client.CSRFValid("bad") {
		t.Fatal("local session helpers returned incorrect results")
	}
	client.mu.Lock()
	client.expiresAt = time.Now().UTC().Add(-time.Minute)
	client.mu.Unlock()
	if client.ValidateLocal("local") {
		t.Fatal("expired local session remained valid")
	}

	client.wsMu.Lock()
	client.wsGeneration = 3
	client.wsCancel = func() {}
	client.wsMu.Unlock()
	if !client.currentWebSocket(3) || client.currentWebSocket(2) {
		t.Fatal("WebSocket generation check failed")
	}
	if client.installWebSocket(2, nil) || !client.installWebSocket(3, nil) {
		t.Fatal("WebSocket install generation check failed")
	}
	client.clearWebSocket(2, nil)
	client.clearWebSocket(3, nil)
	client.startWebSocket()
	client.stopWebSocket()
	if client.currentWebSocket(client.wsGeneration) {
		t.Fatal("stopped WebSocket remained active")
	}
	client.invalidateRemoteSession(context.Background())
	if client.ValidateLocal("local") || client.SessionCookie() != "" {
		t.Fatal("remote invalidation did not clear local state")
	}
}

func TestAppCoverageRemoteErrorsAndRequestValidation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			w.Header().Set("Location", "/other")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":"SESSION_REPLACED","detail":"replaced"}`))
	}))
	defer server.Close()
	client := New(config.Config{DataDir: t.TempDir()})
	client.mu.Lock()
	client.serverURL = server.URL
	client.serverToken = "server-token"
	client.localSession = "local"
	client.csrfToken = "csrf"
	client.expiresAt = time.Now().UTC().Add(time.Minute)
	client.mu.Unlock()
	if err := client.serverRequest(context.Background(), server.URL, http.MethodPost, "/redirect", nil, "token", nil); err == nil {
		t.Fatal("redirect response was followed or accepted")
	}
	if err := client.serverRequest(context.Background(), "://bad", http.MethodGet, "/path", nil, "", nil); err == nil {
		t.Fatal("invalid request base URL was accepted")
	}
	if err := client.serverRequest(context.Background(), server.URL, http.MethodPost, "/path", map[string]interface{}{"function": func() {}}, "token", nil); err == nil {
		t.Fatal("non-JSON request payload was accepted")
	}
	var output map[string]interface{}
	err := client.Proxy(context.Background(), http.MethodGet, "/api/v1/dashboard", nil, "", &output)
	var remote RemoteError
	if !errors.As(err, &remote) || remote.Code != "SESSION_REPLACED" {
		t.Fatalf("remote session replacement error=%T %v", err, err)
	}
	if client.SessionCookie() != "" || client.CSRFValid("csrf") {
		t.Fatal("remote session replacement did not clear runtime state")
	}
}
