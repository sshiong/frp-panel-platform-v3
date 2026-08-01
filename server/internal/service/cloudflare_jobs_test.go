package service

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/ricardo/frp-panel-platform/server/internal/config"
	"github.com/ricardo/frp-panel-platform/server/internal/crypto"
	"github.com/ricardo/frp-panel-platform/server/internal/db"
)

type cloudflareRoundTripper func(*http.Request) (*http.Response, error)

func (fn cloudflareRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) { return fn(req) }

func TestCloudflareTokenAndDomainJobs(t *testing.T) {
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
	cfg := config.Config{DataDir: root, Environment: "development", AdminPassword: "Admin-Password-2026!", SessionTTLHours: 12, PortStart: 6000, PortEnd: 6999, FRPSPublicHost: "frp.example.com", FRPSPublicPort: 7000, CloudflareAPIBaseURL: "https://api.example.test/client/v4"}
	app := New(database, cfg, secrets)
	if _, err := app.EnsureAdmin(context.Background()); err != nil {
		t.Fatal(err)
	}
	admin, err := app.Login(context.Background(), "admin", cfg.AdminPassword, "admin_panel", "127.0.0.1", "test")
	if err != nil {
		t.Fatal(err)
	}
	user, initial, err := app.CreateUser(context.Background(), AuthContext{UserID: admin.User.ID, Role: "admin", SessionID: admin.SessionID, Generation: 1}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	clientLogin, err := app.Login(context.Background(), "alice", initial, "client_panel", "127.0.0.1", "test")
	if err != nil {
		t.Fatal(err)
	}
	if clientLogin.RuntimeCredential == "" || clientLogin.FRPUsername == "" || clientLogin.FRPSecret == "" {
		t.Fatalf("client login must receive runtime credentials in memory: %#v", clientLogin)
	}
	userContext, err := app.Authenticate(context.Background(), clientLogin.Token)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.ChangePassword(context.Background(), userContext, initial, "Alice-Password-2026!"); err != nil {
		t.Fatal(err)
	}

	var createdRecord bool
	app.CloudflareHTTPClient = &http.Client{Transport: cloudflareRoundTripper(func(req *http.Request) (*http.Response, error) {
		var payload interface{}
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/client/v4/user/tokens/verify":
			payload = map[string]interface{}{"success": true}
		case req.Method == http.MethodGet && req.URL.Path == "/client/v4/zones":
			payload = map[string]interface{}{"success": true, "result": []map[string]string{{"id": "zone-1", "name": "example.com"}}, "result_info": map[string]int{"page": 1, "total_pages": 1}}
		case req.Method == http.MethodGet && req.URL.Path == "/client/v4/zones/zone-1/dns_records":
			payload = map[string]interface{}{"success": true, "result": []interface{}{}}
		case req.Method == http.MethodPost && req.URL.Path == "/client/v4/zones/zone-1/dns_records":
			createdRecord = true
			payload = map[string]interface{}{"success": true, "result": map[string]interface{}{"id": "record-1", "type": "CNAME", "name": "app.example.com", "content": "frp.example.com", "ttl": 300, "proxied": false}}
		default:
			payload = map[string]interface{}{"success": false, "errors": []map[string]string{{"message": "unexpected request"}}}
		}
		encoded, _ := json.Marshal(payload)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(encoded)), Header: make(http.Header), Request: req}, nil
	})}
	if err := app.SaveCloudflareToken(context.Background(), userContext, "cf-token-with-enough-length"); err != nil {
		t.Fatal(err)
	}
	tokenJob, err := app.Jobs.Claim(context.Background())
	if err != nil || tokenJob.Type != "cloudflare_token_verify" {
		t.Fatalf("token job: %#v %v", tokenJob, err)
	}
	if err := app.handleJob(context.Background(), tokenJob); err != nil {
		t.Fatal(err)
	}
	if err := app.Jobs.Complete(context.Background(), tokenJob.ID); err != nil {
		t.Fatal(err)
	}
	var tokenStatus string
	if err := database.QueryRow(`SELECT status FROM cloudflare_credentials WHERE user_id=?`, user.ID).Scan(&tokenStatus); err != nil || tokenStatus != "valid" {
		t.Fatalf("token status: %q %v", tokenStatus, err)
	}

	mapping, err := app.CreateMapping(context.Background(), userContext, MappingRequest{Name: "web", ProxyType: "http", LocalIP: "127.0.0.1", LocalPort: 8080}, "idempotency-web")
	if err != nil {
		t.Fatal(err)
	}
	domain, err := app.CreateDomain(context.Background(), userContext, DomainRequest{MappingID: mapping.ID, Hostname: "APP.Example.com.", HTTPSMode: "http_only"})
	if err != nil {
		t.Fatal(err)
	}
	domainJob, err := app.Jobs.Claim(context.Background())
	if err != nil || domainJob.Type != "domain_dns_sync" {
		t.Fatalf("domain job: %#v %v", domainJob, err)
	}
	if err := app.handleJob(context.Background(), domainJob); err != nil {
		t.Fatal(err)
	}
	if err := app.Jobs.Complete(context.Background(), domainJob.ID); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := database.QueryRow(`SELECT status FROM domain_bindings WHERE id=?`, domain.ID).Scan(&status); err != nil || status != "pending_router" {
		t.Fatalf("domain status: %q %v", status, err)
	}
	if !createdRecord {
		t.Fatal("expected DNS create request")
	}
	var dnsCount int
	if err := database.QueryRow(`SELECT COUNT(1) FROM dns_records WHERE domain_binding_id=? AND managed_by_panel=1`, domain.ID).Scan(&dnsCount); err != nil || dnsCount != 1 {
		t.Fatalf("dns record count: %d %v", dnsCount, err)
	}
	routerJob, err := app.Jobs.Claim(context.Background())
	if err != nil || routerJob.Type != "router_snapshot_apply" {
		t.Fatalf("router job: %#v %v", routerJob, err)
	}
	if err := app.handleJob(context.Background(), routerJob); err != nil {
		t.Fatal(err)
	}
	if err := app.Jobs.Complete(context.Background(), routerJob.ID); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT status FROM domain_bindings WHERE id=?`, domain.ID).Scan(&status); err != nil || status != "pending_client" {
		t.Fatalf("domain status before client apply: %q %v", status, err)
	}
	if err := app.ApplyResult(context.Background(), userContext, ApplyResultRequest{Status: "succeeded", ConfigVersion: 2, AppliedConfigHash: "hash", ClientPanelVersion: "test", FRPCVersion: "test"}); err != nil {
		t.Fatal(err)
	}
	routerJob, err = app.Jobs.Claim(context.Background())
	if err != nil || routerJob.Type != "router_snapshot_apply" {
		t.Fatalf("router refresh job: %#v %v", routerJob, err)
	}
	if err := app.handleJob(context.Background(), routerJob); err != nil {
		t.Fatal(err)
	}
	if err := app.Jobs.Complete(context.Background(), routerJob.ID); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT status FROM domain_bindings WHERE id=?`, domain.ID).Scan(&status); err != nil || status != "active" {
		t.Fatalf("domain status after client apply: %q %v", status, err)
	}
}
