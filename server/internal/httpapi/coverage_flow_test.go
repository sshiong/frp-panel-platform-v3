package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ricardo/frp-panel-platform/server/internal/config"
	"github.com/ricardo/frp-panel-platform/server/internal/crypto"
	"github.com/ricardo/frp-panel-platform/server/internal/db"
	"github.com/ricardo/frp-panel-platform/server/internal/service"
)

type coverageHTTPResult struct {
	status  int
	headers http.Header
	body    []byte
}

func TestServerHTTPAPIUserAndAdminFlow(t *testing.T) {
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
	webDir := filepath.Join(root, "admin-web")
	if err := os.MkdirAll(webDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(webDir, "index.html"), []byte("<!doctype html><title>coverage</title>"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(webDir, "favicon.svg"), []byte("<svg/>"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{DataDir: root, Environment: "development", AdminPassword: "Admin-Password-2026!", SessionTTLHours: 12, PortStart: 6000, PortEnd: 6999, FRPSBindPort: 7000, FRPSPublicHost: "frp.example.com", FRPSPublicPort: 7000, RouterSnapshotDir: filepath.Join(root, "router"), AdminWebDir: webDir, RouterControlTarget: "http://127.0.0.1:7400", RouterBusinessTarget: "http://127.0.0.1:8080"}
	application := service.New(database, cfg, secrets)
	if _, err := application.EnsureAdmin(context.Background()); err != nil {
		t.Fatal(err)
	}
	api := New(application, slog.New(slog.NewTextHandler(io.Discard, nil)))
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(api.Handler())
	server.Listener = listener
	server.Start()
	defer server.Close()
	httpClient := server.Client()

	request := func(method, path, body, token string, headers map[string]string) coverageHTTPResult {
		t.Helper()
		var reader io.Reader
		if body != "" {
			reader = strings.NewReader(body)
		}
		req, err := http.NewRequest(method, server.URL+path, reader)
		if err != nil {
			t.Fatal(err)
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		for key, value := range headers {
			req.Header.Set(key, value)
		}
		if token != "" && (method == http.MethodPost || method == http.MethodPut || method == http.MethodDelete || method == http.MethodPatch) && req.Header.Get("Idempotency-Key") == "" {
			req.Header.Set("Idempotency-Key", "coverage-auto-"+shortID())
		}
		response, err := httpClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		encoded, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return coverageHTTPResult{status: response.StatusCode, headers: response.Header.Clone(), body: encoded}
	}
	mustStatus := func(result coverageHTTPResult, status int) {
		t.Helper()
		if result.status != status {
			t.Fatalf("status=%d want=%d body=%s", result.status, status, result.body)
		}
	}
	parse := func(result coverageHTTPResult, target interface{}) {
		t.Helper()
		if err := json.Unmarshal(result.body, target); err != nil {
			t.Fatalf("decode %s: %v", result.body, err)
		}
	}
	key := func(value string) map[string]string { return map[string]string{"Idempotency-Key": value} }

	mustStatus(request(http.MethodGet, "/healthz", "", "", nil), http.StatusOK)
	mustStatus(request(http.MethodGet, "/metrics", "", "", nil), http.StatusOK)
	mustStatus(request(http.MethodGet, "/", "", "", nil), http.StatusOK)
	mustStatus(request(http.MethodGet, "/favicon.svg", "", "", nil), http.StatusOK)
	mustStatus(request(http.MethodOptions, "/api/v1/compatibility", "", "", map[string]string{"Origin": "http://127.0.0.1:5173"}), http.StatusNoContent)
	mustStatus(request(http.MethodGet, "/api/v1/compatibility", "", "", nil), http.StatusOK)
	mustStatus(request(http.MethodPost, "/api/v1/auth/admin-login", `{"username":"admin","password":"wrong-password"}`, "", nil), http.StatusUnauthorized)
	adminLoginHTTP := request(http.MethodPost, "/api/v1/auth/admin-login", `{"username":"admin","password":"Admin-Password-2026!"}`, "", map[string]string{"X-Request-ID": "coverage-admin-login"})
	mustStatus(adminLoginHTTP, http.StatusOK)
	var adminLoginResponse service.LoginResult
	parse(adminLoginHTTP, &adminLoginResponse)
	if adminLoginResponse.RequestID != "coverage-admin-login" || adminLoginHTTP.headers.Get("Set-Cookie") == "" {
		t.Fatalf("admin login did not return session metadata: %#v headers=%v", adminLoginResponse, adminLoginHTTP.headers)
	}

	adminLogin, err := application.Login(context.Background(), "admin", cfg.AdminPassword, "admin_panel", "127.0.0.1", "coverage-admin")
	if err != nil {
		t.Fatal(err)
	}
	admin, err := application.Authenticate(context.Background(), adminLogin.Token)
	if err != nil {
		t.Fatal(err)
	}
	user, initialPassword, err := application.CreateUser(context.Background(), admin, "http-coverage-user")
	if err != nil {
		t.Fatal(err)
	}
	if user.ID == "" || initialPassword == "" {
		t.Fatal("coverage user was not created")
	}

	clientLoginHTTP := request(http.MethodPost, "/api/v1/auth/client-login", `{"username":"http-coverage-user","password":"`+initialPassword+`"}`, "", nil)
	mustStatus(clientLoginHTTP, http.StatusOK)
	var clientLogin service.LoginResult
	parse(clientLoginHTTP, &clientLogin)
	if clientLogin.Token == "" || !clientLogin.User.MustChangePassword {
		t.Fatalf("client login did not expose initial credential state: %#v", clientLogin)
	}
	clientToken := clientLogin.Token
	mustStatus(request(http.MethodGet, "/api/v1/config/full", "", clientToken, nil), http.StatusForbidden)
	clientPassword := "Client-Password-2026!"
	mustStatus(request(http.MethodPost, "/api/v1/auth/change-password", `{"current_password":"`+initialPassword+`","new_password":"`+clientPassword+`"}`, clientToken, key("coverage-password-000001")), http.StatusOK)

	mustStatus(request(http.MethodGet, "/api/v1/me", "", clientToken, nil), http.StatusOK)
	mustStatus(request(http.MethodGet, "/api/v1/dashboard", "", clientToken, nil), http.StatusOK)
	mustStatus(request(http.MethodGet, "/api/v1/mappings?page=1&page_size=50", "", clientToken, nil), http.StatusOK)
	mustStatus(request(http.MethodGet, "/api/v1/domains?page=1&page_size=50", "", clientToken, nil), http.StatusOK)

	tcpBody := `{"name":"http-coverage-tcp","proxy_type":"tcp","local_ip":"127.0.0.1","local_port":8080}`
	tcpResponse := request(http.MethodPost, "/api/v1/mappings", tcpBody, clientToken, key("coverage-http-map-000001"))
	mustStatus(tcpResponse, http.StatusCreated)
	var tcpMapping service.Mapping
	parse(tcpResponse, &tcpMapping)
	if tcpMapping.ID == "" {
		t.Fatal("mapping endpoint returned no id")
	}
	updatedBody := `{"name":"http-coverage-tcp-updated","proxy_type":"tcp","local_ip":"127.0.0.1","local_port":8081}`
	updateResponse := request(http.MethodPut, "/api/v1/mappings/"+tcpMapping.ID, updatedBody, clientToken, key("coverage-http-map-update"))
	mustStatus(updateResponse, http.StatusOK)
	toggleBody := `{"enabled":false}`
	mustStatus(request(http.MethodPost, "/api/v1/mappings/"+tcpMapping.ID+"/toggle", toggleBody, clientToken, key("coverage-http-toggle-off")), http.StatusOK)
	mustStatus(request(http.MethodPost, "/api/v1/mappings/"+tcpMapping.ID+"/toggle", `{"enabled":true}`, clientToken, key("coverage-http-toggle-on")), http.StatusOK)

	httpResponse := request(http.MethodPost, "/api/v1/mappings", `{"name":"http-coverage-http","proxy_type":"http","local_ip":"127.0.0.1","local_port":8082}`, clientToken, key("coverage-http-map-000002"))
	mustStatus(httpResponse, http.StatusCreated)
	var httpMapping service.Mapping
	parse(httpResponse, &httpMapping)
	domainResponse := request(http.MethodPost, "/api/v1/domains", `{"mapping_id":"`+httpMapping.ID+`","hostname":"panel.example.com","https_mode":"http_only","http_redirect":false,"dns_type":"CNAME","dns_content":"frp.example.com","dns_ttl":300}`, clientToken, key("coverage-http-domain-000001"))
	mustStatus(domainResponse, http.StatusAccepted)
	var domain service.Domain
	parse(domainResponse, &domain)
	clientContext, err := application.Authenticate(context.Background(), clientToken)
	if err != nil {
		t.Fatal(err)
	}
	pluginMeta := `"frp_runtime_credential":"` + clientLogin.RuntimeCredential + `","frp_user_secret":"` + clientLogin.FRPSecret + `","session_generation":"` + fmt.Sprint(clientContext.Generation) + `"`
	pluginLogin := `{"version":"0.68.0","user":"` + clientLogin.FRPUsername + `","metas":{` + pluginMeta + `}}`
	pluginLoginEnvelope := `{"content":` + pluginLogin + `}`
	pluginLoginResponse := request(http.MethodPost, "/internal/frp/plugin?op=Login&version=0.1.0", pluginLoginEnvelope, "", nil)
	mustStatus(pluginLoginResponse, http.StatusOK)
	var pluginDecision map[string]interface{}
	parse(pluginLoginResponse, &pluginDecision)
	if pluginDecision["unchange"] != true {
		t.Fatalf("valid FRP Login was not allowed: %#v", pluginDecision)
	}
	mustStatus(request(http.MethodGet, "/internal/frp/plugin", "", "", nil), http.StatusMethodNotAllowed)
	mustStatus(request(http.MethodPost, "/internal/frp/plugin?op=Login&version=9.9.9", pluginLoginEnvelope, "", nil), http.StatusBadRequest)
	mustStatus(request(http.MethodPost, "/internal/frp/plugin?op=Login", `{"content":null}`, "", nil), http.StatusBadRequest)
	mustStatus(request(http.MethodPost, "/internal/frp/plugin?op=Login", `{"content":{"version":"0.67.0","user":"`+clientLogin.FRPUsername+`","metas":{`+pluginMeta+`}}}`, "", nil), http.StatusOK)
	validProxy := `{"user":{"user":"` + clientLogin.FRPUsername + `","metas":{` + pluginMeta + `}},"proxy_name":"mapping-` + httpMapping.ID + `","proxy_type":"http","remote_port":0,"custom_domains":["panel.example.com"],"metas":{"mapping_id":"` + httpMapping.ID + `","mapping_revision":"1"}}`
	validProxyResponse := request(http.MethodPost, "/internal/frp/plugin?op=NewProxy&version=0.1.0", `{"content":`+validProxy+`}`, "", nil)
	mustStatus(validProxyResponse, http.StatusOK)
	parse(validProxyResponse, &pluginDecision)
	if pluginDecision["unchange"] != true {
		t.Fatalf("valid FRP NewProxy was not allowed: %#v", pluginDecision)
	}
	badProxy := strings.Replace(validProxy, `"proxy_name":"mapping-`+httpMapping.ID+`"`, `"proxy_name":"forged-proxy"`, 1)
	badProxyResponse := request(http.MethodPost, "/internal/frp/plugin?op=NewProxy", `{"content":`+badProxy+`}`, "", nil)
	mustStatus(badProxyResponse, http.StatusOK)
	parse(badProxyResponse, &pluginDecision)
	if pluginDecision["reject"] != true {
		t.Fatalf("forged FRP proxy name was accepted: %#v", pluginDecision)
	}
	legacyPlugin := `{"operation":"Ping","frp_username":"` + clientLogin.FRPUsername + `","runtime_credential":"` + clientLogin.RuntimeCredential + `","session_generation":` + fmt.Sprint(clientContext.Generation) + `}`
	mustStatus(request(http.MethodPost, "/internal/frp/plugin", legacyPlugin, "", nil), http.StatusOK)
	mustStatus(request(http.MethodGet, "/api/v1/config/full", "", clientToken, nil), http.StatusOK)
	mustStatus(request(http.MethodGet, "/api/v1/config/signing-key", "", clientToken, nil), http.StatusOK)
	configResponse := request(http.MethodGet, "/api/v1/config/full", "", clientToken, nil)
	var snapshot service.ConfigSnapshot
	parse(configResponse, &snapshot)
	applyBody, _ := json.Marshal(service.ApplyResultRequest{Status: "succeeded", ConfigVersion: snapshot.ConfigVersion, AppliedConfigHash: snapshot.ConfigHash, ClientPanelVersion: "0.1.0", FRPCVersion: "0.68.0"})
	mustStatus(request(http.MethodPost, "/api/v1/config/apply-result", string(applyBody), clientToken, key("coverage-http-apply-result")), http.StatusOK)
	mustStatus(request(http.MethodPost, "/api/v1/session/heartbeat", `{"client_panel_version":"0.1.0","frpc_version":"0.68.0"}`, clientToken, nil), http.StatusOK)
	mustStatus(request(http.MethodGet, "/api/v1/operations?page=1&page_size=50", "", clientToken, nil), http.StatusOK)
	mustStatus(request(http.MethodPost, "/api/v1/domains/"+domain.ID+"/dns-action", `{"action":"adopt"}`, clientToken, key("coverage-http-dns-action")), http.StatusAccepted)

	reauthResponse := request(http.MethodPost, "/api/v1/auth/reauth", `{"current_password":"Admin-Password-2026!"}`, adminLogin.Token, nil)
	mustStatus(reauthResponse, http.StatusOK)
	var reauth struct {
		Ticket string `json:"reauth_ticket"`
	}
	parse(reauthResponse, &reauth)
	if reauth.Ticket == "" {
		t.Fatal("admin reauth ticket missing")
	}
	mustStatus(request(http.MethodGet, "/api/v1/admin/users?page=1&page_size=50", "", adminLogin.Token, nil), http.StatusOK)
	mustStatus(request(http.MethodGet, "/api/v1/admin/stats", "", adminLogin.Token, nil), http.StatusOK)
	mustStatus(request(http.MethodGet, "/api/v1/admin/operations?page=1&page_size=50", "", adminLogin.Token, nil), http.StatusOK)
	mustStatus(request(http.MethodGet, "/api/v1/admin/router/status", "", adminLogin.Token, nil), http.StatusOK)
	mustStatus(request(http.MethodPost, "/api/v1/admin/router/rebuild", `{"reauth_ticket":"`+reauth.Ticket+`"}`, adminLogin.Token, nil), http.StatusAccepted)
	mustStatus(request(http.MethodPost, "/api/v1/cloudflare/token", `{"token":"coverage-cloudflare-token-0123456789","reauth_ticket":"`+reauth.Ticket+`"}`, adminLogin.Token, nil), http.StatusAccepted)
	mustStatus(request(http.MethodGet, "/api/v1/cloudflare/status", "", adminLogin.Token, nil), http.StatusOK)
	mustStatus(request(http.MethodDelete, "/api/v1/cloudflare/token", `{"reauth_ticket":"`+reauth.Ticket+`"}`, adminLogin.Token, nil), http.StatusOK)

	createdResponse := request(http.MethodPost, "/api/v1/admin/users", `{"username":"http-created-user","reauth_ticket":"`+reauth.Ticket+`"}`, adminLogin.Token, nil)
	mustStatus(createdResponse, http.StatusCreated)
	var created struct {
		User service.UserRecord `json:"user"`
	}
	parse(createdResponse, &created)
	if created.User.ID == "" {
		t.Fatal("admin user endpoint returned no user")
	}
	mustStatus(request(http.MethodPost, "/api/v1/admin/users/"+created.User.ID+"/status", `{"status":"disabled","reauth_ticket":"`+reauth.Ticket+`"}`, adminLogin.Token, nil), http.StatusOK)
	mustStatus(request(http.MethodPost, "/api/v1/admin/users/"+created.User.ID+"/status", `{"status":"active","reauth_ticket":"`+reauth.Ticket+`"}`, adminLogin.Token, nil), http.StatusOK)
	mustStatus(request(http.MethodPost, "/api/v1/admin/users/"+created.User.ID+"/reset-password", `{"reauth_ticket":"`+reauth.Ticket+`"}`, adminLogin.Token, nil), http.StatusOK)
	resetKey := key("coverage-http-admin-frp-reset")
	resetKey["Idempotency-Key"] = "coverage-http-admin-frp-reset"
	mustStatus(request(http.MethodPost, "/api/v1/admin/users/"+created.User.ID+"/reset-frp-credential", `{"reauth_ticket":"`+reauth.Ticket+`"}`, adminLogin.Token, resetKey), http.StatusOK)
	var retryOperationID string
	if err := database.QueryRow(`SELECT id FROM operations WHERE resource_type='domain' AND resource_id=? AND operation_type='create' ORDER BY created_at LIMIT 1`, domain.ID).Scan(&retryOperationID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE operations SET status='failed',phase='dns',error_code='COVERAGE_RETRY',error_message='coverage' WHERE id=?`, retryOperationID); err != nil {
		t.Fatal(err)
	}
	mustStatus(request(http.MethodPost, "/api/v1/operations/"+retryOperationID+"/retry", "", adminLogin.Token, nil), http.StatusAccepted)
	deleteHeaders := key("coverage-http-admin-delete")
	mustStatus(request(http.MethodDelete, "/api/v1/admin/users/"+created.User.ID+"?force=true", `{"reauth_ticket":"`+reauth.Ticket+`"}`, adminLogin.Token, deleteHeaders), http.StatusAccepted)
	mustStatus(request(http.MethodGet, "/api/v1/ws?protocol_version=v2", "", clientToken, nil), http.StatusUpgradeRequired)
	backupResponse := request(http.MethodPost, "/api/v1/admin/backups", `{"password":"Backup-Password-2026!","reauth_ticket":"`+reauth.Ticket+`"}`, adminLogin.Token, nil)
	mustStatus(backupResponse, http.StatusCreated)

	mustStatus(request(http.MethodDelete, "/api/v1/domains/"+domain.ID, "", clientToken, key("coverage-http-domain-delete")), http.StatusAccepted)
	mustStatus(request(http.MethodDelete, "/api/v1/mappings/"+tcpMapping.ID, "", clientToken, key("coverage-http-map-delete")), http.StatusAccepted)
	clientReauth := request(http.MethodPost, "/api/v1/auth/reauth", `{"current_password":"`+clientPassword+`"}`, clientToken, nil)
	mustStatus(clientReauth, http.StatusOK)
	var clientTicket struct {
		Ticket string `json:"reauth_ticket"`
	}
	parse(clientReauth, &clientTicket)
	clientResetHeaders := key("coverage-http-client-frp-reset")
	mustStatus(request(http.MethodPost, "/api/v1/auth/reset-frp-credential", `{"reauth_ticket":"`+clientTicket.Ticket+`"}`, clientToken, clientResetHeaders), http.StatusOK)
	mustStatus(request(http.MethodPost, "/api/v1/auth/logout", nilString(), adminLogin.Token, nil), http.StatusOK)
	// Client FRP credential rotation already invalidated the client session. The
	// response path is still explicitly covered by the Server auth middleware.
	if result := request(http.MethodGet, "/api/v1/dashboard", "", clientToken, nil); result.status != http.StatusUnauthorized {
		t.Fatalf("rotated client session remained valid: status=%d body=%s", result.status, result.body)
	}
}

func nilString() string { return "" }
