package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ricardo/frp-panel-platform/server/internal/config"
	"github.com/ricardo/frp-panel-platform/server/internal/crypto"
	"github.com/ricardo/frp-panel-platform/server/internal/db"
	"github.com/ricardo/frp-panel-platform/server/internal/service"
)

func TestHTTPContractSmokeCoversProblemDetailsAuthAndPagination(t *testing.T) {
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
	app := service.New(database, config.Config{DataDir: root, Environment: "development", AdminPassword: "Admin-Password-2026!", SessionTTLHours: 12}, secrets)
	if _, err := app.EnsureAdmin(context.Background()); err != nil {
		t.Fatal(err)
	}
	login, err := app.Login(context.Background(), "admin", "Admin-Password-2026!", "admin_panel", "127.0.0.1", "contract-test")
	if err != nil {
		t.Fatal(err)
	}
	handler := New(app, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler()

	problemRequest := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin-login", strings.NewReader("{"))
	problemRequest.RemoteAddr = "127.0.0.1:12000"
	problemResponse := httptest.NewRecorder()
	handler.ServeHTTP(problemResponse, problemRequest)
	if problemResponse.Code != http.StatusBadRequest || !strings.HasPrefix(problemResponse.Header().Get("Content-Type"), "application/problem+json") {
		t.Fatalf("invalid JSON contract: status=%d content-type=%q", problemResponse.Code, problemResponse.Header().Get("Content-Type"))
	}
	var problem map[string]interface{}
	if err := json.Unmarshal(problemResponse.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"type", "title", "status", "detail", "code", "request_id"} {
		if problem[field] == nil || problem[field] == "" {
			t.Fatalf("Problem Details missing %q: %#v", field, problem)
		}
	}

	compatibilityRequest := httptest.NewRequest(http.MethodGet, "/api/v1/compatibility", nil)
	compatibilityResponse := httptest.NewRecorder()
	handler.ServeHTTP(compatibilityResponse, compatibilityRequest)
	if compatibilityResponse.Code != http.StatusOK {
		t.Fatalf("compatibility status=%d", compatibilityResponse.Code)
	}
	unsupportedProtocol := httptest.NewRequest(http.MethodGet, "/api/v1/compatibility", nil)
	unsupportedProtocol.Header.Set("X-FRP-Protocol-Version", "v9")
	unsupportedProtocolResponse := httptest.NewRecorder()
	handler.ServeHTTP(unsupportedProtocolResponse, unsupportedProtocol)
	if unsupportedProtocolResponse.Code != http.StatusUpgradeRequired || !strings.Contains(unsupportedProtocolResponse.Body.String(), "UPGRADE_REQUIRED") || unsupportedProtocolResponse.Header().Get("Upgrade-Required") != "v1" {
		t.Fatalf("unsupported protocol contract: status=%d headers=%v body=%s", unsupportedProtocolResponse.Code, unsupportedProtocolResponse.Header(), unsupportedProtocolResponse.Body.String())
	}
	var compatibility map[string]interface{}
	if err := json.Unmarshal(compatibilityResponse.Body.Bytes(), &compatibility); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"server_version", "minimum_client_version", "latest_client_version", "minimum_frpc_version", "protocol_version", "config_schema_version"} {
		if compatibility[field] == nil || compatibility[field] == "" {
			t.Fatalf("compatibility missing %q: %#v", field, compatibility)
		}
	}

	legacyClientLogin := httptest.NewRequest(http.MethodPost, "/api/v1/auth/client-login", strings.NewReader(`{"username":"admin","password":"Admin-Password-2026!"}`))
	legacyClientLogin.RemoteAddr = "127.0.0.1:12000"
	legacyClientLogin.Header.Set("X-FRP-Client-Version", "0.0.9")
	legacyClientLoginResponse := httptest.NewRecorder()
	handler.ServeHTTP(legacyClientLoginResponse, legacyClientLogin)
	if legacyClientLoginResponse.Code != http.StatusUpgradeRequired || legacyClientLoginResponse.Header().Get("Upgrade-Required") != "client/0.1.0" || !strings.Contains(legacyClientLoginResponse.Body.String(), "CLIENT_VERSION_UNSUPPORTED") || !strings.Contains(legacyClientLoginResponse.Body.String(), "upgrade_required") {
		t.Fatalf("legacy Client version was not rejected with upgrade metadata: status=%d headers=%v body=%s", legacyClientLoginResponse.Code, legacyClientLoginResponse.Header(), legacyClientLoginResponse.Body.String())
	}

	reauthRequest := httptest.NewRequest(http.MethodPost, "/api/v1/auth/reauth", strings.NewReader(`{"current_password":"Admin-Password-2026!"}`))
	reauthRequest.RemoteAddr = "127.0.0.1:12000"
	reauthRequest.Header.Set("Authorization", "Bearer "+login.Token)
	reauthRequest.Header.Set("Idempotency-Key", "contract-reauth-key-0001")
	reauthResponse := httptest.NewRecorder()
	handler.ServeHTTP(reauthResponse, reauthRequest)
	if reauthResponse.Code != http.StatusOK {
		t.Fatalf("reauth idempotency first request status=%d body=%s", reauthResponse.Code, reauthResponse.Body.String())
	}
	var firstReauth map[string]interface{}
	if err := json.Unmarshal(reauthResponse.Body.Bytes(), &firstReauth); err != nil {
		t.Fatal(err)
	}
	if firstReauth["reauth_ticket"] == nil || firstReauth["request_id"] == nil {
		t.Fatalf("write response metadata missing: %#v", firstReauth)
	}
	retryRequest := httptest.NewRequest(http.MethodPost, "/api/v1/auth/reauth", strings.NewReader(`{"current_password":"Admin-Password-2026!"}`))
	retryRequest.RemoteAddr = "127.0.0.1:12000"
	retryRequest.Header.Set("Authorization", "Bearer "+login.Token)
	retryRequest.Header.Set("Idempotency-Key", "contract-reauth-key-0001")
	retryResponse := httptest.NewRecorder()
	handler.ServeHTTP(retryResponse, retryRequest)
	var repeatedReauth map[string]interface{}
	if retryResponse.Code != http.StatusOK || json.Unmarshal(retryResponse.Body.Bytes(), &repeatedReauth) != nil || repeatedReauth["reauth_ticket"] != firstReauth["reauth_ticket"] {
		t.Fatalf("idempotent reauth did not replay encrypted response: status=%d body=%s first=%v repeated=%v", retryResponse.Code, retryResponse.Body.String(), firstReauth, repeatedReauth)
	}
	conflictRequest := httptest.NewRequest(http.MethodPost, "/api/v1/auth/reauth", strings.NewReader(`{"current_password":"different-password-2026!"}`))
	conflictRequest.RemoteAddr = "127.0.0.1:12000"
	conflictRequest.Header.Set("Authorization", "Bearer "+login.Token)
	conflictRequest.Header.Set("Idempotency-Key", "contract-reauth-key-0001")
	conflictResponse := httptest.NewRecorder()
	handler.ServeHTTP(conflictResponse, conflictRequest)
	if conflictResponse.Code != http.StatusConflict || !strings.Contains(conflictResponse.Body.String(), "IDEMPOTENCY_KEY_REUSED") {
		t.Fatalf("idempotency body conflict was not rejected: status=%d body=%s", conflictResponse.Code, conflictResponse.Body.String())
	}

	mappingsRequest := httptest.NewRequest(http.MethodGet, "/api/v1/mappings?page=2&page_size=1", nil)
	mappingsRequest.RemoteAddr = "127.0.0.1:12000"
	mappingsRequest.Header.Set("Authorization", "Bearer "+login.Token)
	mappingsResponse := httptest.NewRecorder()
	handler.ServeHTTP(mappingsResponse, mappingsRequest)
	if mappingsResponse.Code != http.StatusOK {
		t.Fatalf("paginated mappings status=%d body=%s", mappingsResponse.Code, mappingsResponse.Body.String())
	}
	var page map[string]interface{}
	if err := json.Unmarshal(mappingsResponse.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"items", "config_version", "page", "page_size", "total"} {
		if page[field] == nil {
			t.Fatalf("paginated mappings missing %q: %#v", field, page)
		}
	}
	if page["page"].(float64) != 2 || page["page_size"].(float64) != 1 {
		t.Fatalf("pagination parameters were not honored: %#v", page)
	}

	unknownFieldRequest := httptest.NewRequest(http.MethodPost, "/api/v1/mappings", strings.NewReader(`{"name":"contract","unknown":true}`))
	unknownFieldRequest.RemoteAddr = "127.0.0.1:12000"
	unknownFieldRequest.Header.Set("Authorization", "Bearer "+login.Token)
	unknownFieldRequest.Header.Set("Idempotency-Key", "contract-key-123456")
	unknownFieldResponse := httptest.NewRecorder()
	handler.ServeHTTP(unknownFieldResponse, unknownFieldRequest)
	if unknownFieldResponse.Code != http.StatusBadRequest || !strings.Contains(unknownFieldResponse.Body.String(), "INVALID_JSON") {
		t.Fatalf("unknown JSON field was not rejected as Problem Details: status=%d body=%s", unknownFieldResponse.Code, unknownFieldResponse.Body.String())
	}

	missingKeyRequest := httptest.NewRequest(http.MethodPost, "/api/v1/mappings", strings.NewReader(`{"name":"contract","proxy_type":"tcp","local_ip":"127.0.0.1","local_port":8080}`))
	missingKeyRequest.RemoteAddr = "127.0.0.1:12000"
	missingKeyRequest.Header.Set("Authorization", "Bearer "+login.Token)
	missingKeyResponse := httptest.NewRecorder()
	handler.ServeHTTP(missingKeyResponse, missingKeyRequest)
	if missingKeyResponse.Code != http.StatusPreconditionRequired || !strings.Contains(missingKeyResponse.Body.String(), "IDEMPOTENCY_KEY_REQUIRED") {
		t.Fatalf("missing idempotency key contract: status=%d body=%s", missingKeyResponse.Code, missingKeyResponse.Body.String())
	}
}
