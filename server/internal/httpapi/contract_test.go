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
	var compatibility map[string]interface{}
	if err := json.Unmarshal(compatibilityResponse.Body.Bytes(), &compatibility); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"minimum_client_version", "latest_client_version", "minimum_frpc_version", "protocol_version", "config_schema_version"} {
		if compatibility[field] == nil || compatibility[field] == "" {
			t.Fatalf("compatibility missing %q: %#v", field, compatibility)
		}
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
