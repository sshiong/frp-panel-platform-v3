package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ricardo/frp-panel-platform/client/internal/config"
	"github.com/ricardo/frp-panel-platform/client/internal/supervisor"
)

func TestPerformanceConfigSubmitToClientApply(t *testing.T) {
	if testing.Short() || os.Getenv("FRP_PERF_SCALE") != "1" {
		t.Skip("set FRP_PERF_SCALE=1 to run the client synchronization acceptance profile")
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := supervisor.Snapshot{
		SchemaVersion:     "v1",
		ConfigVersion:     1,
		UserID:            "perf-user",
		SessionGeneration: 1,
		IssuedAt:          time.Now().UTC().Format(time.RFC3339Nano),
		ExpiresAt:         time.Now().UTC().Add(5 * time.Minute).Format(time.RFC3339Nano),
		ConfigHash:        "perf-config-hash",
		SigningKeyID:      "perf-key",
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
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/auth/client-login":
			_, _ = io.WriteString(w, `{"token":"server-token","session_expires_at":"2030-01-01T00:00:00Z","runtime_credential":"runtime-token","frp_username":"perf-user","frp_secret":"user-secret","frps_transport_secret":"transport-secret","user":{"id":"perf-user","username":"perf-user","role":"user","status":"active","must_change_password":false,"must_change_username":false}}`)
		case "/api/v1/config/full":
			_ = json.NewEncoder(w).Encode(snapshot)
		case "/api/v1/config/signing-key":
			_ = json.NewEncoder(w).Encode(map[string]string{"public_key": hex.EncodeToString(publicKey)})
		case "/api/v1/config/apply-result":
			applyCount.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		case "/api/v1/ws":
			w.WriteHeader(http.StatusUpgradeRequired)
		default:
			w.WriteHeader(http.StatusNotFound)
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
	started := time.Now()
	if _, err := client.Login(t.Context(), server.URL, "perf-user", "Perf-User-Password-2026!"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		client.stopWebSocket()
		_ = client.Supervisor.Stop(t.Context())
		_ = client.Supervisor.ClearRuntimeSecrets()
	}()
	duration := time.Since(started)
	if duration > 5*time.Second {
		t.Fatalf("PERF-006 failed: config submit to simulated Client apply took %s", duration)
	}
	if applyCount.Load() != 1 || client.SupervisorStatus().AppliedVersion != 1 {
		t.Fatalf("Client did not acknowledge exactly one applied snapshot: count=%d status=%#v", applyCount.Load(), client.SupervisorStatus())
	}
	t.Logf("PERF-006 config submit to Client apply=%s", duration)
}
