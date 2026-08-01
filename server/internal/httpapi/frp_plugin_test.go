package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ricardo/frp-panel-platform/server/internal/config"
	"github.com/ricardo/frp-panel-platform/server/internal/crypto"
	"github.com/ricardo/frp-panel-platform/server/internal/db"
	"github.com/ricardo/frp-panel-platform/server/internal/service"
)

func TestFRPPluginUsesRealServerPluginEnvelope(t *testing.T) {
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
	adminLogin, err := app.Login(context.Background(), "admin", cfg.AdminPassword, "admin_panel", "127.0.0.1", "plugin-test")
	if err != nil {
		t.Fatal(err)
	}
	admin, err := app.Authenticate(context.Background(), adminLogin.Token)
	if err != nil {
		t.Fatal(err)
	}
	_, password, err := app.CreateUser(context.Background(), admin, "alice")
	if err != nil {
		t.Fatal(err)
	}
	clientLogin, err := app.Login(context.Background(), "alice", password, "client_panel", "127.0.0.1", "plugin-test")
	if err != nil {
		t.Fatal(err)
	}
	user, err := app.Authenticate(context.Background(), clientLogin.Token)
	if err != nil {
		t.Fatal(err)
	}
	remotePort := 6123
	mapping, err := app.CreateMapping(context.Background(), user, service.MappingRequest{Name: "ssh", ProxyType: "tcp", LocalIP: "127.0.0.1", LocalPort: 22, RemotePort: &remotePort}, "plugin-mapping-key-123456")
	if err != nil {
		t.Fatal(err)
	}
	if clientLogin.FRPUsername == "" || clientLogin.RuntimeCredential == "" || mapping.RemotePort == nil {
		t.Fatalf("fixture did not issue FRP runtime data: login=%#v mapping=%#v", clientLogin, mapping)
	}

	server := httptest.NewServer(New(app, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler())
	defer server.Close()
	post := func(operation string, content map[string]interface{}) (int, frpPluginResponse) {
		t.Helper()
		body, marshalErr := json.Marshal(map[string]interface{}{"content": content})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		request, requestErr := http.NewRequest(http.MethodPost, server.URL+"/internal/frp/plugin?version=0.1.0&op="+operation, strings.NewReader(string(body)))
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		request.Header.Set("Content-Type", "application/json")
		response, requestErr := http.DefaultClient.Do(request)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		defer response.Body.Close()
		var decoded frpPluginResponse
		if decodeErr := json.NewDecoder(response.Body).Decode(&decoded); decodeErr != nil {
			t.Fatal(decodeErr)
		}
		return response.StatusCode, decoded
	}

	globalMetas := map[string]string{
		"frp_runtime_credential": clientLogin.RuntimeCredential,
		"session_generation":     strconv.FormatInt(user.Generation, 10),
		"frp_user_secret":        clientLogin.FRPSecret,
	}
	status, loginResponse := post("Login", map[string]interface{}{"version": "0.68.0", "user": clientLogin.FRPUsername, "metas": globalMetas})
	if status != http.StatusOK || loginResponse.Reject || !loginResponse.Unchange {
		t.Fatalf("real Login plugin request was not allowed: status=%d response=%#v", status, loginResponse)
	}

	proxyMetas := map[string]string{"mapping_id": mapping.ID, "mapping_revision": strconv.FormatInt(mapping.Revision, 10)}
	status, proxyResponse := post("NewProxy", map[string]interface{}{
		"user":        map[string]interface{}{"user": clientLogin.FRPUsername, "metas": globalMetas, "run_id": "run-1"},
		"proxy_name":  "mapping-" + mapping.ID,
		"proxy_type":  "tcp",
		"remote_port": *mapping.RemotePort,
		"metas":       proxyMetas,
	})
	if status != http.StatusOK || proxyResponse.Reject || !proxyResponse.Unchange {
		t.Fatalf("real NewProxy plugin request was not allowed: status=%d response=%#v", status, proxyResponse)
	}

	staleMetas := map[string]string{"frp_runtime_credential": clientLogin.RuntimeCredential, "session_generation": strconv.FormatInt(user.Generation+1, 10), "frp_user_secret": clientLogin.FRPSecret}
	status, staleResponse := post("Ping", map[string]interface{}{"user": map[string]interface{}{"user": clientLogin.FRPUsername, "metas": staleMetas}})
	if status != http.StatusOK || !staleResponse.Reject || !strings.Contains(staleResponse.RejectReason, "SESSION_GENERATION_MISMATCH") {
		t.Fatalf("stale FRP session was not rejected: status=%d response=%#v", status, staleResponse)
	}

	status, closeResponse := post("CloseProxy", map[string]interface{}{"user": map[string]interface{}{"user": clientLogin.FRPUsername, "metas": globalMetas}, "proxy_name": "mapping-" + mapping.ID})
	if status != http.StatusOK || closeResponse.Reject || !closeResponse.Unchange {
		t.Fatalf("real CloseProxy plugin request was not allowed: status=%d response=%#v", status, closeResponse)
	}
}
