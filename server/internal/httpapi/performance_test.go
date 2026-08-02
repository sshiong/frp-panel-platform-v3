package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/ricardo/frp-panel-platform/server/internal/config"
	"github.com/ricardo/frp-panel-platform/server/internal/crypto"
	"github.com/ricardo/frp-panel-platform/server/internal/db"
	"github.com/ricardo/frp-panel-platform/server/internal/id"
	"github.com/ricardo/frp-panel-platform/server/internal/router"
	"github.com/ricardo/frp-panel-platform/server/internal/service"
)

// TestPerformanceBaseline is an opt-in local control-plane gate. It is kept
// out of ordinary unit-test runs because the acceptance profile intentionally
// creates concurrent traffic and should be run on the target-like host with
// FRP_PERF=1.
func TestPerformanceBaseline(t *testing.T) {
	if testing.Short() || os.Getenv("FRP_PERF") != "1" {
		t.Skip("set FRP_PERF=1 to run the acceptance performance profile")
	}
	app, server, login := performanceFixture(t)
	token := login.Token
	defer server.Close()

	readErrors, readP95 := concurrentRequests(100, func(index int) error {
		request, err := http.NewRequest(http.MethodGet, server.URL+"/api/v1/dashboard", nil)
		if err != nil {
			return err
		}
		request.Header.Set("Authorization", "Bearer "+token)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, response.Body)
		if response.StatusCode != http.StatusOK {
			return &httpError{status: response.StatusCode}
		}
		return nil
	})
	if readErrors != 0 || readP95 > 300*time.Millisecond {
		t.Fatalf("PERF-001 failed: errors=%d p95=%s threshold=300ms", readErrors, readP95)
	}

	writeErrors, writeP95 := concurrentRequests(20, func(index int) error {
		payload, _ := json.Marshal(map[string]interface{}{"name": "perf-" + stringID(index), "proxy_type": "tcp", "local_ip": "127.0.0.1", "local_port": 10000 + index})
		request, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/mappings", bytes.NewReader(payload))
		if err != nil {
			return err
		}
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", "perf-write-key-"+stringID(index))
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, response.Body)
		if response.StatusCode != http.StatusCreated {
			return &httpError{status: response.StatusCode}
		}
		return nil
	})
	if writeErrors != 0 || writeP95 > 800*time.Millisecond {
		t.Fatalf("PERF-002 failed: errors=%d p95=%s threshold=800ms", writeErrors, writeP95)
	}
	_ = app
	t.Logf("PERF-001 reads=100 errors=%d p95=%s; PERF-002 writes=20 errors=%d p95=%s", readErrors, readP95, writeErrors, writeP95)
}

// TestPerformanceSessionReplacement measures the bounded invalidation path
// required by PERF-007: an old HTTP session, WebSocket and FRP Plugin login
// must stop being useful immediately after the replacement login commits.
func TestPerformanceSessionReplacement(t *testing.T) {
	if testing.Short() || os.Getenv("FRP_PERF_SCALE") != "1" {
		t.Skip("set FRP_PERF_SCALE=1 to run the session replacement acceptance profile")
	}
	app, server, oldLogin := performanceFixture(t)
	oldUser, err := app.Authenticate(t.Context(), oldLogin.Token)
	if err != nil {
		t.Fatal(err)
	}

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/api/v1/ws"
	dialer := websocket.Dialer{HandshakeTimeout: 5 * time.Second}
	connection, response, err := dialer.Dial(wsURL, http.Header{
		"Authorization": []string{"Bearer " + oldLogin.Token},
		"Origin":        []string{"http://127.0.0.1:7410"},
	})
	if err != nil {
		if response != nil {
			t.Fatalf("old WebSocket dial failed with status %d: %v", response.StatusCode, err)
		}
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
	var connected wsEnvelope
	if err := connection.ReadJSON(&connected); err != nil || connected.Type != "connected" {
		t.Fatalf("old WebSocket did not connect: %#v %v", connected, err)
	}

	started := time.Now()
	loginBody := bytes.NewBufferString(`{"username":"perf-user","password":"Perf-User-Password-2026!"}`)
	loginRequest, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/auth/client-login", loginBody)
	if err != nil {
		t.Fatal(err)
	}
	loginRequest.Header.Set("Content-Type", "application/json")
	loginRequest.Header.Set("X-FRP-Protocol-Version", "v1")
	loginResponse, err := http.DefaultClient.Do(loginRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer loginResponse.Body.Close()
	var replacement service.LoginResult
	if err := json.NewDecoder(loginResponse.Body).Decode(&replacement); err != nil {
		t.Fatal(err)
	}
	if loginResponse.StatusCode != http.StatusOK || replacement.Token == "" {
		t.Fatalf("replacement login failed: status=%d result=%#v", loginResponse.StatusCode, replacement)
	}

	_ = connection.SetReadDeadline(time.Now().Add(5 * time.Second))
	var replaced wsEnvelope
	if err := connection.ReadJSON(&replaced); err != nil || replaced.Type != "session_replaced" {
		t.Fatalf("old WebSocket was not invalidated: %#v %v", replaced, err)
	}
	websocketInvalidation := time.Since(started)
	if websocketInvalidation > 5*time.Second {
		t.Fatalf("PERF-007 WebSocket invalidation took %s", websocketInvalidation)
	}

	started = time.Now()
	oldRequest, err := http.NewRequest(http.MethodGet, server.URL+"/api/v1/dashboard", nil)
	if err != nil {
		t.Fatal(err)
	}
	oldRequest.Header.Set("Authorization", "Bearer "+oldLogin.Token)
	oldResponse, err := http.DefaultClient.Do(oldRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer oldResponse.Body.Close()
	var oldProblem map[string]interface{}
	_ = json.NewDecoder(oldResponse.Body).Decode(&oldProblem)
	httpInvalidation := time.Since(started)
	if oldResponse.StatusCode != http.StatusUnauthorized || oldProblem["code"] != "SESSION_REPLACED" || httpInvalidation > 5*time.Second {
		t.Fatalf("PERF-007 old HTTP session remained usable: status=%d code=%v duration=%s", oldResponse.StatusCode, oldProblem["code"], httpInvalidation)
	}

	started = time.Now()
	pluginPayload, err := json.Marshal(map[string]interface{}{"content": map[string]interface{}{
		"version": "0.68.0",
		"user":    oldLogin.FRPUsername,
		"metas": map[string]string{
			"frp_runtime_credential": oldLogin.RuntimeCredential,
			"session_generation":     strconv.FormatInt(oldUser.Generation, 10),
			"frp_user_secret":        oldLogin.FRPSecret,
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	pluginRequest, err := http.NewRequest(http.MethodPost, server.URL+"/internal/frp/plugin?version=0.1.0&op=Login", bytes.NewReader(pluginPayload))
	if err != nil {
		t.Fatal(err)
	}
	pluginRequest.Header.Set("Content-Type", "application/json")
	pluginResponse, err := http.DefaultClient.Do(pluginRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer pluginResponse.Body.Close()
	var pluginReject frpPluginResponse
	if err := json.NewDecoder(pluginResponse.Body).Decode(&pluginReject); err != nil {
		t.Fatal(err)
	}
	pluginInvalidation := time.Since(started)
	if pluginResponse.StatusCode != http.StatusOK || !pluginReject.Reject || pluginInvalidation > 30*time.Second {
		t.Fatalf("PERF-007 old FRP login remained usable: status=%d reject=%v reason=%q duration=%s", pluginResponse.StatusCode, pluginReject.Reject, pluginReject.RejectReason, pluginInvalidation)
	}
	t.Logf("PERF-007 session replacement: websocket=%s http=%s old-frp-login=%s", websocketInvalidation, httpInvalidation, pluginInvalidation)
}

// TestPerformanceScale is the target-size local profile for the remaining
// control-plane baselines. It is opt-in because it deliberately creates 3,000
// durable resources and measures filesystem-backed Router snapshot work.
func TestPerformanceScale(t *testing.T) {
	if testing.Short() || os.Getenv("FRP_PERF_SCALE") != "1" {
		t.Skip("set FRP_PERF_SCALE=1 to run the target-size acceptance profile")
	}
	app, _ := scalePerformanceFixture(t, 1000, 2000)
	started := time.Now()
	snapshot, err := app.BuildRouterSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := router.NewRuntime(app.Crypto.RouterKey, "http://127.0.0.1:7400", "http://127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Load(snapshot); err != nil {
		t.Fatal(err)
	}
	routerDuration := time.Since(started)
	if routerDuration > 5*time.Second {
		t.Fatalf("PERF-003 failed: 1000 mappings + 2000 domains took %s", routerDuration)
	}

	configApp, configPrincipal := scalePerformanceFixture(t, 200, 0)
	started = time.Now()
	configSnapshot, err := configApp.FullConfig(context.Background(), configPrincipal)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := configSnapshot
	signature, err := base64.RawURLEncoding.DecodeString(unsigned.Signature)
	if err != nil {
		t.Fatal(err)
	}
	unsigned.Signature = ""
	encoded, err := json.Marshal(unsigned)
	if err != nil || !ed25519.Verify(configApp.Crypto.SignKey.Public().(ed25519.PublicKey), encoded, signature) {
		t.Fatalf("PERF-005 snapshot signature verification failed: %v", err)
	}
	configDuration := time.Since(started)
	if configDuration > 2*time.Second {
		t.Fatalf("PERF-005 failed: 200 mapping config generation/signature took %s", configDuration)
	}
	t.Logf("PERF-003 router snapshot generate/apply=%s; PERF-005 200 mapping config generate/sign=%s", routerDuration, configDuration)
}

func scalePerformanceFixture(t *testing.T, mappingCount, domainCount int) (*service.App, service.AuthContext) {
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
	cfg := config.Config{DataDir: root, Environment: "development", AdminPassword: "Admin-Password-2026!", SessionTTLHours: 12, PortStart: 6000, PortEnd: 6999, RouterSnapshotDir: filepath.Join(root, "router"), RouterControlHosts: []string{"panel.example.com"}}
	app := service.New(database, cfg, secrets)
	if _, err := app.EnsureAdmin(context.Background()); err != nil {
		t.Fatal(err)
	}
	login, err := app.Login(context.Background(), "admin", cfg.AdminPassword, "admin_panel", "127.0.0.1", "performance-scale")
	if err != nil {
		t.Fatal(err)
	}
	principal, err := app.Authenticate(context.Background(), login.Token)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := database.Begin()
	if err != nil {
		t.Fatal(err)
	}
	mappingIDs := make([]string, 0, mappingCount)
	for index := 0; index < mappingCount; index++ {
		mappingID := id.New()
		mappingIDs = append(mappingIDs, mappingID)
		revisionID := id.New()
		if _, err := tx.Exec(`INSERT INTO mappings(id,user_id,name,proxy_type,lifecycle_status,desired_state,observed_state,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`, mappingID, principal.UserID, fmt.Sprintf("scale-%04d", index), "http", "running", "enabled", "running", now, now); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
		if _, err := tx.Exec(`INSERT INTO mapping_revisions(id,mapping_id,revision,local_ip,local_port,status,created_at,applied_at) VALUES(?,?,?,?,?,?,?,?)`, revisionID, mappingID, 1, "127.0.0.1", 1000+index, "active", now, now); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
		if _, err := tx.Exec(`UPDATE mappings SET active_revision_id=? WHERE id=?`, revisionID, mappingID); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
	}
	for index := 0; index < domainCount; index++ {
		mappingID := mappingIDs[index%len(mappingIDs)]
		domainID := id.New()
		hostname := fmt.Sprintf("app-%04d.example.com", index)
		if _, err := tx.Exec(`INSERT INTO domain_bindings(id,user_id,mapping_id,hostname,normalized_domain,https_mode,http_redirect,status,revision,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, domainID, principal.UserID, mappingID, hostname, hostname, "http_only", 0, "active", 1, now, now); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return app, principal
}

type httpError struct{ status int }

func (e *httpError) Error() string { return "unexpected HTTP status" }

func performanceFixture(t *testing.T) (*service.App, *httptest.Server, service.LoginResult) {
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
	cfg := config.Config{DataDir: root, Environment: "development", AdminPassword: "Admin-Password-2026!", SessionTTLHours: 12, PortStart: 6000, PortEnd: 6999, AllowedOrigins: []string{"http://127.0.0.1:7410"}}
	app := service.New(database, cfg, secrets)
	if _, err := app.EnsureAdmin(context.Background()); err != nil {
		t.Fatal(err)
	}
	adminLogin, err := app.Login(context.Background(), "admin", cfg.AdminPassword, "admin_panel", "127.0.0.1", "performance")
	if err != nil {
		t.Fatal(err)
	}
	admin, err := app.Authenticate(context.Background(), adminLogin.Token)
	if err != nil {
		t.Fatal(err)
	}
	_, password, err := app.CreateUser(context.Background(), admin, "perf-user")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE users SET max_mappings=100,max_pending_mappings=100,max_pending_port_leases=100 WHERE username='perf-user'`); err != nil {
		t.Fatal(err)
	}
	clientLogin, err := app.Login(context.Background(), "perf-user", password, "client_panel", "127.0.0.1", "performance")
	if err != nil {
		t.Fatal(err)
	}
	user, err := app.Authenticate(context.Background(), clientLogin.Token)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.ChangePassword(context.Background(), user, password, "Perf-User-Password-2026!"); err != nil {
		t.Fatal(err)
	}
	clientLogin, err = app.Login(context.Background(), "perf-user", "Perf-User-Password-2026!", "client_panel", "127.0.0.1", "performance")
	if err != nil {
		t.Fatal(err)
	}
	api := New(app, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return app, httptest.NewServer(api.Handler()), clientLogin
}

func concurrentRequests(count int, request func(int) error) (int, time.Duration) {
	start := make(chan struct{})
	durations := make([]time.Duration, count)
	var errorsCount atomic.Int32
	var wg sync.WaitGroup
	for index := 0; index < count; index++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			<-start
			started := time.Now()
			if err := request(index); err != nil {
				errorsCount.Add(1)
			}
			durations[index] = time.Since(started)
		}(index)
	}
	close(start)
	wg.Wait()
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	position := (len(durations)*95 + 99) / 100
	if position < 1 {
		position = 1
	}
	return int(errorsCount.Load()), durations[position-1]
}

func stringID(value int) string {
	const alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
	if value == 0 {
		return "0"
	}
	encoded := ""
	for value > 0 {
		encoded = string(alphabet[value%len(alphabet)]) + encoded
		value /= len(alphabet)
	}
	return encoded
}
