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

	var createdRecord, deletedRecord bool
	var createdPayload map[string]interface{}
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
			_ = json.NewDecoder(req.Body).Decode(&createdPayload)
			payload = map[string]interface{}{"success": true, "result": map[string]interface{}{"id": "record-1", "type": "A", "name": "app.example.com", "content": "192.0.2.10", "ttl": 120, "proxied": false}}
		case req.Method == http.MethodDelete && req.URL.Path == "/client/v4/zones/zone-1/dns_records/record-1":
			deletedRecord = true
			payload = map[string]interface{}{"success": true, "result": map[string]interface{}{}}
		default:
			payload = map[string]interface{}{"success": false, "errors": []map[string]string{{"message": "unexpected request"}}}
		}
		encoded, _ := json.Marshal(payload)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(encoded)), Header: make(http.Header), Request: req}, nil
	})}
	reauthTicket, _, err := app.IssueReauthTicket(context.Background(), userContext, "Alice-Password-2026!")
	if err != nil {
		t.Fatal(err)
	}
	if err := app.SaveCloudflareToken(context.Background(), userContext, "cf-token-with-enough-length", reauthTicket); err != nil {
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
	domain, err := app.CreateDomain(context.Background(), userContext, DomainRequest{MappingID: mapping.ID, Hostname: "APP.Example.com.", HTTPSMode: "http_only", DNSRecordType: "A", DNSContent: "192.0.2.10", DNSTTL: 120})
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
	if createdPayload["type"] != "A" || createdPayload["content"] != "192.0.2.10" || int(createdPayload["ttl"].(float64)) != 120 || createdPayload["proxied"] != false {
		t.Fatalf("unexpected DNS payload: %#v", createdPayload)
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

	deleteOperation, err := app.DeleteMapping(context.Background(), userContext, mapping.ID, false)
	if err != nil || deleteOperation == "" {
		t.Fatalf("mapping delete request: %q %v", deleteOperation, err)
	}
	if err := database.QueryRow(`SELECT status FROM domain_bindings WHERE id=?`, domain.ID).Scan(&status); err != nil || status != "deleting" {
		t.Fatalf("domain must remain available for DNS compensation: %q %v", status, err)
	}
	if err := app.ApplyResult(context.Background(), userContext, ApplyResultRequest{Status: "succeeded", ConfigVersion: 3, AppliedConfigHash: "hash-3", ClientPanelVersion: "test", FRPCVersion: "test"}); err != nil {
		t.Fatal(err)
	}
	deleteJob, err := app.Jobs.Claim(context.Background())
	if err != nil || deleteJob.Type != "domain_delete" {
		t.Fatalf("domain cleanup job: %#v %v", deleteJob, err)
	}
	if err := app.handleJob(context.Background(), deleteJob); err != nil {
		t.Fatal(err)
	}
	if err := app.Jobs.Complete(context.Background(), deleteJob.ID); err != nil {
		t.Fatal(err)
	}
	if !deletedRecord {
		t.Fatal("managed DNS record was not deleted during mapping compensation")
	}
	var remaining int
	if err := database.QueryRow(`SELECT COUNT(1) FROM mappings WHERE id=?`, mapping.ID).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("mapping was not finalized after domain cleanup: %d %v", remaining, err)
	}
	if err := database.QueryRow(`SELECT status FROM operations WHERE id=?`, deleteOperation).Scan(&status); err != nil || status != "succeeded" {
		t.Fatalf("mapping delete operation: %q %v", status, err)
	}

	remotePort := 6100
	portMapping, err := app.CreateMapping(context.Background(), userContext, MappingRequest{Name: "tcp", ProxyType: "tcp", LocalIP: "127.0.0.1", LocalPort: 9000, RemotePort: &remotePort}, "idempotency-tcp")
	if err != nil {
		t.Fatal(err)
	}
	if err := app.ApplyResult(context.Background(), userContext, ApplyResultRequest{Status: "succeeded", ConfigVersion: 4, AppliedConfigHash: "hash-4", ClientPanelVersion: "test", FRPCVersion: "test"}); err != nil {
		t.Fatal(err)
	}
	updatedPort := 6101
	if _, err := app.UpdateMapping(context.Background(), userContext, portMapping.ID, MappingRequest{Name: "tcp", ProxyType: "tcp", LocalIP: "127.0.0.1", LocalPort: 9000, RemotePort: &updatedPort}, "idempotency-tcp-update"); err != nil {
		t.Fatal(err)
	}
	if err := app.ApplyResult(context.Background(), userContext, ApplyResultRequest{Status: "succeeded", ConfigVersion: 5, AppliedConfigHash: "hash-5", ClientPanelVersion: "test", FRPCVersion: "test"}); err != nil {
		t.Fatal(err)
	}
	var oldPort, newPort int
	if err := database.QueryRow(`SELECT COUNT(1) FROM port_leases WHERE mapping_id=? AND remote_port=?`, portMapping.ID, remotePort).Scan(&oldPort); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT COUNT(1) FROM port_leases WHERE mapping_id=? AND remote_port=? AND lease_role='active'`, portMapping.ID, updatedPort).Scan(&newPort); err != nil {
		t.Fatal(err)
	}
	if oldPort != 0 || newPort != 1 {
		t.Fatalf("port lease rotation was not applied: old=%d new=%d", oldPort, newPort)
	}
	portForIdempotency := 6102
	idempotentMapping, err := app.CreateMapping(context.Background(), userContext, MappingRequest{Name: "idempotent-delete", ProxyType: "tcp", LocalIP: "127.0.0.1", LocalPort: 9001, RemotePort: &portForIdempotency}, "idempotency-delete-create")
	if err != nil {
		t.Fatal(err)
	}
	firstDelete, err := app.DeleteMapping(context.Background(), userContext, idempotentMapping.ID, false, "delete-key-123456789")
	if err != nil {
		t.Fatal(err)
	}
	secondDelete, err := app.DeleteMapping(context.Background(), userContext, idempotentMapping.ID, false, "delete-key-123456789")
	if err != nil || firstDelete != secondDelete {
		t.Fatalf("delete idempotency failed: first=%q second=%q err=%v", firstDelete, secondDelete, err)
	}
	if err := app.ClearCloudflareToken(context.Background(), userContext, "wrong-password"); err != ErrInvalidCredentials {
		t.Fatalf("cloudflare clear accepted an invalid re-authentication: %v", err)
	}
	if err := app.ClearCloudflareToken(context.Background(), userContext, "Alice-Password-2026!"); err != nil {
		t.Fatalf("cloudflare clear with current password failed: %v", err)
	}
	if status, err := app.CloudflareStatus(context.Background(), user.ID); err != nil || status["configured"] != false {
		t.Fatalf("cloudflare status remained configured after clear: %#v %v", status, err)
	}
}
