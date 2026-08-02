package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ricardo/frp-panel-platform/server/internal/config"
	"github.com/ricardo/frp-panel-platform/server/internal/crypto"
	"github.com/ricardo/frp-panel-platform/server/internal/db"
	"github.com/ricardo/frp-panel-platform/server/internal/service"
)

func TestAdminCookieWritesRequireSessionBoundCSRF(t *testing.T) {
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
	cfg := config.Config{DataDir: root, Environment: "development", AdminPassword: "Admin-Password-2026!", SessionTTLHours: 12, PortStart: 6000, PortEnd: 6999}
	app := service.New(database, cfg, secrets)
	if _, err := app.EnsureAdmin(context.Background()); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(New(app, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler())
	defer server.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}
	loginBody := strings.NewReader(`{"username":"admin","password":"Admin-Password-2026!"}`)
	loginRequest, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/auth/admin-login", loginBody)
	if err != nil {
		t.Fatal(err)
	}
	loginRequest.Header.Set("Content-Type", "application/json")
	loginResponse, err := client.Do(loginRequest)
	if err != nil {
		t.Fatal(err)
	}
	_ = loginResponse.Body.Close()
	if loginResponse.StatusCode != http.StatusOK {
		t.Fatalf("admin login status=%d", loginResponse.StatusCode)
	}

	postUser := func(csrf, reauthTicket string) *http.Response {
		t.Helper()
		body := `{"username":"alice"}`
		if reauthTicket != "" {
			body = `{"username":"alice","reauth_ticket":"` + reauthTicket + `"}`
		}
		request, requestErr := http.NewRequest(http.MethodPost, server.URL+"/api/v1/admin/users", strings.NewReader(body))
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", "csrf-test-user-123456")
		if csrf != "" {
			request.Header.Set("X-CSRF-Token", csrf)
		}
		response, requestErr := client.Do(request)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		return response
	}
	withoutCSRF := postUser("", "")
	_ = withoutCSRF.Body.Close()
	if withoutCSRF.StatusCode != http.StatusForbidden {
		t.Fatalf("cookie write without CSRF status=%d, want 403", withoutCSRF.StatusCode)
	}

	csrf := ""
	parsedURL, _ := url.Parse(server.URL)
	for _, cookie := range jar.Cookies(parsedURL) {
		if cookie.Name == serverCSRFCookie {
			csrf = cookie.Value
		}
	}
	if csrf == "" {
		t.Fatal("admin login did not set CSRF cookie")
	}
	withoutReauth := postUser(csrf, "")
	_ = withoutReauth.Body.Close()
	if withoutReauth.StatusCode != http.StatusUnauthorized {
		t.Fatalf("cookie write without reauthentication status=%d, want 401", withoutReauth.StatusCode)
	}
	reauthRequest, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/auth/reauth", strings.NewReader(`{"current_password":"Admin-Password-2026!"}`))
	if err != nil {
		t.Fatal(err)
	}
	reauthRequest.Header.Set("Content-Type", "application/json")
	reauthRequest.Header.Set("X-CSRF-Token", csrf)
	reauthRequest.Header.Set("Idempotency-Key", "csrf-test-reauth-123456")
	reauthResponse, err := client.Do(reauthRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer reauthResponse.Body.Close()
	if reauthResponse.StatusCode != http.StatusOK {
		t.Fatalf("reauth status=%d", reauthResponse.StatusCode)
	}
	var reauth struct {
		Ticket string `json:"reauth_ticket"`
	}
	if err := json.NewDecoder(reauthResponse.Body).Decode(&reauth); err != nil {
		t.Fatal(err)
	}
	if reauth.Ticket == "" {
		t.Fatal("reauth did not return a ticket")
	}
	withCSRF := postUser(csrf, reauth.Ticket)
	_ = withCSRF.Body.Close()
	if withCSRF.StatusCode != http.StatusCreated {
		t.Fatalf("cookie write with CSRF status=%d, want 201", withCSRF.StatusCode)
	}
}
