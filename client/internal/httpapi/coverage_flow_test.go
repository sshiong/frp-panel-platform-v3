package httpapi

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ricardo/frp-panel-platform/client/internal/app"
	"github.com/ricardo/frp-panel-platform/client/internal/config"
	"github.com/ricardo/frp-panel-platform/client/internal/supervisor"
)

func TestClientHTTPAPICoverageFlow(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := supervisor.Snapshot{SchemaVersion: "v1", ConfigVersion: 1, UserID: "client-api-user", SessionGeneration: 1, IssuedAt: time.Now().UTC().Format(time.RFC3339Nano), ExpiresAt: time.Now().UTC().Add(5 * time.Minute).Format(time.RFC3339Nano), ConfigHash: "client-api-hash", SigningKeyID: "client-api-key", Payload: map[string]interface{}{"mappings": []interface{}{}}}
	unsigned := snapshot
	unsigned.Signature = ""
	encoded, err := json.Marshal(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, encoded))
	remoteHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/auth/client-login":
			var input map[string]string
			_ = json.NewDecoder(r.Body).Decode(&input)
			if input["password"] == "bad" {
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{"code": "AUTH_INVALID_CREDENTIALS", "detail": "invalid"})
				return
			}
			_, _ = io.WriteString(w, `{"token":"remote-session","session_expires_at":"2030-01-01T00:00:00Z","runtime_credential":"runtime","frp_username":"client-api-user","frp_secret":"secret","frps_transport_secret":"transport","user":{"id":"client-api-user","username":"client-api-user","role":"user","status":"active","must_change_password":false,"must_change_username":false}}`)
		case "/api/v1/config/full":
			_ = json.NewEncoder(w).Encode(snapshot)
		case "/api/v1/config/signing-key":
			_ = json.NewEncoder(w).Encode(map[string]string{"public_key": hex.EncodeToString(publicKey)})
		case "/api/v1/config/apply-result":
			_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		case "/api/v1/auth/reauth":
			_ = json.NewEncoder(w).Encode(map[string]string{"reauth_ticket": "ticket"})
		case "/api/v1/auth/reset-frp-credential":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "rotated", "secret_version": 2})
		case "/api/v1/ws":
			w.WriteHeader(http.StatusUpgradeRequired)
		default:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "items": []interface{}{}})
		}
	})
	remoteListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	remote := httptest.NewUnstartedServer(remoteHandler)
	remote.Listener = remoteListener
	remote.Start()
	defer remote.Close()

	webDir := filepath.Join(t.TempDir(), "client-web")
	if err := os.MkdirAll(webDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(webDir, "index.html"), []byte("<!doctype html><title>client coverage</title>"), 0o600); err != nil {
		t.Fatal(err)
	}
	client := app.New(config.Config{DataDir: t.TempDir(), Environment: "development", ListenAddr: "127.0.0.1:7410", AllowedHost: "127.0.0.1,localhost", AllowedCIDRs: []string{"127.0.0.0/8"}, ClientWebDir: webDir})

	localAPI := New(client)
	localListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	localServer := httptest.NewUnstartedServer(localAPI.Handler())
	localServer.Listener = localListener
	localServer.Start()
	defer localServer.Close()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	httpClient := localServer.Client()
	httpClient.Jar = jar

	request := func(method, path, body string, headers map[string]string) (int, []byte) {
		t.Helper()
		var reader io.Reader
		if body != "" {
			reader = strings.NewReader(body)
		}
		req, err := http.NewRequest(method, localServer.URL+path, reader)
		if err != nil {
			t.Fatal(err)
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		for key, value := range headers {
			req.Header.Set(key, value)
		}
		response, err := httpClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, data
	}
	must := func(status, want int, body []byte) {
		t.Helper()
		if status != want {
			t.Fatalf("status=%d want=%d body=%s", status, want, body)
		}
	}

	status, body := request(http.MethodGet, "/healthz", "", nil)
	must(status, http.StatusOK, body)
	var health map[string]interface{}
	if err := json.Unmarshal(body, &health); err != nil || health["request_id"] == nil {
		t.Fatalf("local success response did not carry request_id: %s", body)
	}
	status, body = request(http.MethodGet, "/healthz", "", map[string]string{"X-FRP-Protocol-Version": "v9"})
	must(status, http.StatusUpgradeRequired, body)
	if !strings.Contains(string(body), "UPGRADE_REQUIRED") || !strings.Contains(string(body), "request_id") {
		t.Fatalf("local protocol error was not a versioned Problem Details response: %s", body)
	}
	status, body = request(http.MethodGet, "/", "", nil)
	must(status, http.StatusOK, body)
	status, body = request(http.MethodOptions, "/api/v1/session", "", map[string]string{"Origin": "http://127.0.0.1:5174"})
	must(status, http.StatusNoContent, body)
	status, body = request(http.MethodPost, "/api/v1/login", `{"server_panel_url":"`+remote.URL+`","username":"client-api-user","password":"bad"}`, nil)
	must(status, http.StatusUnauthorized, body)
	status, body = request(http.MethodPost, "/api/v1/login", `{"server_panel_url":"`+remote.URL+`","username":"client-api-user","password":"Client-Password-2026!"}`, nil)
	must(status, http.StatusOK, body)
	csrf := client.Session().CSRFToken
	if csrf == "" || client.SessionCookie() == "" {
		t.Fatal("client login did not establish local session")
	}

	status, body = request(http.MethodGet, "/api/v1/session", "", nil)
	must(status, http.StatusOK, body)
	status, body = request(http.MethodGet, "/api/v1/dashboard", "", nil)
	must(status, http.StatusOK, body)
	status, body = request(http.MethodGet, "/api/v1/mappings", "", nil)
	must(status, http.StatusOK, body)
	status, body = request(http.MethodGet, "/api/v1/domains", "", nil)
	must(status, http.StatusOK, body)
	status, body = request(http.MethodGet, "/api/v1/config", "", nil)
	must(status, http.StatusOK, body)
	status, body = request(http.MethodGet, "/api/v1/local-status", "", nil)
	must(status, http.StatusOK, body)
	status, body = request(http.MethodGet, "/api/v1/logs", "", nil)
	must(status, http.StatusOK, body)

	status, body = request(http.MethodPost, "/api/v1/password", `{"current_password":"old","new_password":"new-password-2026"}`, map[string]string{"X-CSRF-Token": "bad"})
	must(status, http.StatusForbidden, body)
	writeHeaders := map[string]string{"X-CSRF-Token": csrf, "Idempotency-Key": "client-api-map-create"}
	status, body = request(http.MethodPost, "/api/v1/password", `{"current_password":"old","new_password":"new-password-2026"}`, map[string]string{"X-CSRF-Token": csrf})
	must(status, http.StatusOK, body)
	status, body = request(http.MethodPost, "/api/v1/reauth", `{"current_password":"old"}`, map[string]string{"X-CSRF-Token": csrf})
	must(status, http.StatusOK, body)
	status, body = request(http.MethodPost, "/api/v1/mappings", `{"name":"client-api-map","proxy_type":"tcp","local_ip":"127.0.0.1","local_port":8080}`, writeHeaders)
	must(status, http.StatusCreated, body)
	status, body = request(http.MethodPut, "/api/v1/mappings/coverage-id", `{"name":"client-api-map","proxy_type":"tcp","local_ip":"127.0.0.1","local_port":8081}`, map[string]string{"X-CSRF-Token": csrf, "Idempotency-Key": "client-api-map-update"})
	must(status, http.StatusOK, body)
	status, body = request(http.MethodPost, "/api/v1/mappings/coverage-id/toggle", `{"enabled":false}`, map[string]string{"X-CSRF-Token": csrf, "Idempotency-Key": "client-api-map-toggle"})
	must(status, http.StatusOK, body)
	status, body = request(http.MethodDelete, "/api/v1/mappings/coverage-id", "", map[string]string{"X-CSRF-Token": csrf, "Idempotency-Key": "client-api-map-delete"})
	must(status, http.StatusAccepted, body)
	status, body = request(http.MethodPost, "/api/v1/domains", `{"mapping_id":"coverage-id","hostname":"panel.example.com","https_mode":"http_only"}`, map[string]string{"X-CSRF-Token": csrf, "Idempotency-Key": "client-api-domain-create"})
	must(status, http.StatusAccepted, body)
	status, body = request(http.MethodPost, "/api/v1/domains/coverage-domain/dns-action", `{"action":"adopt"}`, map[string]string{"X-CSRF-Token": csrf, "Idempotency-Key": "client-api-dns-action"})
	must(status, http.StatusAccepted, body)
	status, body = request(http.MethodDelete, "/api/v1/domains/coverage-domain", "", map[string]string{"X-CSRF-Token": csrf, "Idempotency-Key": "client-api-domain-delete"})
	must(status, http.StatusAccepted, body)
	status, body = request(http.MethodPost, "/api/v1/sync", "", map[string]string{"X-CSRF-Token": csrf})
	must(status, http.StatusOK, body)

	status, body = request(http.MethodPost, "/api/v1/logout", "", nil)
	must(status, http.StatusOK, body)
	status, body = request(http.MethodGet, "/api/v1/session", "", nil)
	must(status, http.StatusUnauthorized, body)
	// Log in once more to cover the local FRP reset path, which deliberately
	// clears the cookie after the remote Server revokes the current session.
	status, body = request(http.MethodPost, "/api/v1/login", `{"server_panel_url":"`+remote.URL+`","username":"client-api-user","password":"Client-Password-2026!"}`, nil)
	must(status, http.StatusOK, body)
	csrf = client.Session().CSRFToken
	status, body = request(http.MethodPost, "/api/v1/frp-credential/reset", `{"current_password":"Client-Password-2026!"}`, map[string]string{"X-CSRF-Token": csrf, "Idempotency-Key": "client-api-frp-reset"})
	must(status, http.StatusOK, body)
	status, body = request(http.MethodGet, "/api/v1/session", "", nil)
	must(status, http.StatusUnauthorized, body)

	badRequest := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	badRequest.RemoteAddr = "192.0.2.1:1234"
	badRequest.Host = "evil.example.test"
	recorder := httptest.NewRecorder()
	localAPI.Handler().ServeHTTP(recorder, badRequest)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("LAN/host boundary status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
