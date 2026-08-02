package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ricardo/frp-panel-platform/server/internal/acme"
	"github.com/ricardo/frp-panel-platform/server/internal/jobs"
	"github.com/ricardo/frp-panel-platform/server/internal/providers/cloudflare"
)

type jobsCoverageProvider struct {
	mode string
}

func (p *jobsCoverageProvider) RoundTrip(request *http.Request) (*http.Response, error) {
	status := http.StatusOK
	payload := map[string]interface{}{"success": true}
	path := strings.TrimPrefix(request.URL.Path, "/client/v4")
	switch {
	case path == "/user/tokens/verify":
		if p.mode == "invalid" {
			payload = map[string]interface{}{"success": false}
		}
		if p.mode == "denied" {
			status = http.StatusForbidden
			payload = map[string]interface{}{"success": false, "errors": []map[string]string{{"message": "permission denied"}}}
		}
	case path == "/zones":
		if p.mode == "denied" {
			status = http.StatusForbidden
			payload = map[string]interface{}{"success": false, "errors": []map[string]string{{"message": "zone permission denied"}}}
		} else {
			payload = map[string]interface{}{"success": true, "result": []map[string]string{{"id": "zone-coverage", "name": "example.com"}}, "result_info": map[string]int{"page": 1, "total_pages": 1}}
		}
	case request.Method == http.MethodGet && path == "/zones/zone-coverage/dns_records":
		records := []map[string]interface{}{}
		if p.mode == "conflict" {
			records = []map[string]interface{}{{"id": "record-conflict", "type": "CNAME", "name": "conflict.example.com", "content": "other.example.com", "ttl": 120, "proxied": false}}
		}
		payload = map[string]interface{}{"success": true, "result": records}
	case request.Method == http.MethodPost || request.Method == http.MethodPut:
		payload = map[string]interface{}{"success": true, "result": map[string]interface{}{"id": "record-upserted", "type": "CNAME", "name": "overwrite.example.com", "content": "frp.example.com", "ttl": 300, "proxied": false}}
	case request.Method == http.MethodDelete:
		payload = map[string]interface{}{"success": true, "result": map[string]interface{}{}}
	default:
		payload = map[string]interface{}{"success": true, "result": []interface{}{}}
	}
	encoded, _ := json.Marshal(payload)
	response := &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(encoded)), Request: request}
	response.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
	return response, nil
}

type coverageACMEProvider struct{}

func (coverageACMEProvider) IssueDNS01(_ context.Context, domain string) (acme.Certificate, error) {
	certPEM, privatePEM := testCertificate(nilTestHelper{}, domain)
	return acme.Certificate{CertPEM: certPEM, PrivateKey: privatePEM, NotBefore: time.Now().UTC().Add(-time.Minute), NotAfter: time.Now().UTC().Add(30 * 24 * time.Hour)}, nil
}

// nilTestHelper keeps the tiny certificate helper reusable from a provider
// that is not itself a *testing.T. The helper only uses Helper/Fatal while
// generating test material, so errors here are converted to a panic that
// fails the test immediately.
type nilTestHelper struct{}

func (nilTestHelper) Helper()                   {}
func (nilTestHelper) Fatal(args ...interface{}) { panic(args) }

func TestCloudflareJobsCoverageFailureRecoveryAndACME(t *testing.T) {
	fixture := newServiceCoverageFixture(t)
	ctx := context.Background()
	app := fixture.app
	provider := &jobsCoverageProvider{}
	app.CloudflareHTTPClient = &http.Client{Transport: provider}
	app.Config.CloudflareAPIBaseURL = "https://api.example.test/client/v4"

	if err := app.handleJob(ctx, jobs.Job{Type: "unsupported"}); err == nil {
		t.Fatal("unsupported job type was silently accepted")
	}
	if err := app.handleJob(ctx, jobs.Job{Type: "cloudflare_token_verify"}); err == nil {
		t.Fatal("invalid Cloudflare token job payload was accepted")
	}
	if err := app.deleteDomainExternal(ctx, jobs.Job{}); err == nil {
		t.Fatal("invalid domain deletion payload was accepted")
	}
	if err := app.deleteUserExternal(ctx, jobs.Job{}); err == nil {
		t.Fatal("invalid user deletion payload was accepted")
	}
	if err := app.issueCertificate(ctx, jobs.Job{}); err == nil {
		t.Fatal("invalid ACME job payload was accepted")
	}

	ticket, _, err := app.IssueReauthTicket(ctx, fixture.client, fixture.password)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.SaveCloudflareToken(ctx, fixture.client, "coverage-token-abcdefghijklmnopqrstuvwxyz", ticket); err != nil {
		t.Fatal(err)
	}
	tokenJob, err := app.Jobs.Claim(ctx)
	if err != nil || tokenJob.Type != "cloudflare_token_verify" {
		t.Fatalf("Cloudflare token job=%#v err=%v", tokenJob, err)
	}
	if err := app.handleJob(ctx, tokenJob); err != nil {
		t.Fatal(err)
	}
	if err := app.Jobs.Complete(ctx, tokenJob.ID); err != nil {
		t.Fatal(err)
	}

	mapping, err := app.CreateMapping(ctx, fixture.client, MappingRequest{Name: "jobs-http", ProxyType: "http", LocalIP: "127.0.0.1", LocalPort: 8130}, "jobs-http-map-000001")
	if err != nil {
		t.Fatal(err)
	}
	checkDomain, err := app.CreateDomain(ctx, fixture.client, DomainRequest{MappingID: mapping.ID, Hostname: "check.example.com", HTTPSMode: "http_only"}, "jobs-check-domain-000001")
	if err != nil {
		t.Fatal(err)
	}
	if err := app.syncDomainDNS(ctx, jobs.Job{Payload: map[string]interface{}{"user_id": fixture.client.UserID, "domain_id": checkDomain.ID, "action": "check"}}); err != nil {
		t.Fatal(err)
	}

	provider.mode = "conflict"
	conflictDomain, err := app.CreateDomain(ctx, fixture.client, DomainRequest{MappingID: mapping.ID, Hostname: "conflict.example.com", HTTPSMode: "http_only"}, "jobs-conflict-domain-000001")
	if err != nil {
		t.Fatal(err)
	}
	if err := app.syncDomainDNS(ctx, jobs.Job{Payload: map[string]interface{}{"user_id": fixture.client.UserID, "domain_id": conflictDomain.ID}}); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := app.DB.QueryRowContext(ctx, `SELECT status FROM domain_bindings WHERE id=?`, conflictDomain.ID).Scan(&status); err != nil || status != "dns_error" {
		t.Fatalf("conflicting domain status=%q err=%v", status, err)
	}

	adoptDomain, err := app.CreateDomain(ctx, fixture.client, DomainRequest{MappingID: mapping.ID, Hostname: "adopt.example.com", HTTPSMode: "http_only"}, "jobs-adopt-domain-000001")
	if err != nil {
		t.Fatal(err)
	}
	if err := app.syncDomainDNS(ctx, jobs.Job{Payload: map[string]interface{}{"user_id": fixture.client.UserID, "domain_id": adoptDomain.ID, "action": "adopt"}}); err != nil {
		t.Fatal(err)
	}
	var adopted int
	if err := app.DB.QueryRowContext(ctx, `SELECT adopted FROM dns_records WHERE domain_binding_id=?`, adoptDomain.ID).Scan(&adopted); err != nil || adopted != 1 {
		t.Fatalf("adopted record=%d err=%v", adopted, err)
	}

	overwriteDomain, err := app.CreateDomain(ctx, fixture.client, DomainRequest{MappingID: mapping.ID, Hostname: "overwrite.example.com", HTTPSMode: "http_only"}, "jobs-overwrite-domain-000001")
	if err != nil {
		t.Fatal(err)
	}
	if err := app.syncDomainDNS(ctx, jobs.Job{Payload: map[string]interface{}{"user_id": fixture.client.UserID, "domain_id": overwriteDomain.ID, "action": "overwrite"}}); err != nil {
		t.Fatal(err)
	}

	cancelDomain, err := app.CreateDomain(ctx, fixture.client, DomainRequest{MappingID: mapping.ID, Hostname: "cancel.example.com", HTTPSMode: "http_only"}, "jobs-cancel-domain-000001")
	if err != nil {
		t.Fatal(err)
	}
	if err := app.syncDomainDNS(ctx, jobs.Job{Payload: map[string]interface{}{"user_id": fixture.client.UserID, "domain_id": cancelDomain.ID, "action": "cancel"}}); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.QueryRowContext(ctx, `SELECT status FROM domain_bindings WHERE id=?`, cancelDomain.ID).Scan(&status); err != nil || status != "pending_dns" {
		t.Fatalf("canceled domain status=%q err=%v", status, err)
	}

	managedDomain, err := app.CreateDomain(ctx, fixture.client, DomainRequest{MappingID: mapping.ID, Hostname: "managed.example.com", HTTPSMode: "http_only"}, "jobs-managed-domain-000001")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.ExecContext(ctx, `UPDATE dns_records SET managed_by_panel=1,content='frp.example.com',type='CNAME',ttl=300 WHERE domain_binding_id=?`, managedDomain.ID); err != nil {
		t.Fatal(err)
	}
	provider.mode = "normal"
	if err := app.syncDomainDNS(ctx, jobs.Job{Payload: map[string]interface{}{"user_id": fixture.client.UserID, "domain_id": managedDomain.ID, "action": "sync"}}); err != nil {
		t.Fatal(err)
	}

	permissionDomain, err := app.CreateDomain(ctx, fixture.client, DomainRequest{MappingID: mapping.ID, Hostname: "permission.example.com", HTTPSMode: "http_only"}, "jobs-permission-domain-000001")
	if err != nil {
		t.Fatal(err)
	}
	provider.mode = "denied"
	if err := app.syncDomainDNS(ctx, jobs.Job{Payload: map[string]interface{}{"user_id": fixture.client.UserID, "domain_id": permissionDomain.ID}}); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.QueryRowContext(ctx, `SELECT status FROM domain_bindings WHERE id=?`, permissionDomain.ID).Scan(&status); err != nil || status != "dns_error" {
		t.Fatalf("Cloudflare permission failure was not persisted: status=%q err=%v", status, err)
	}

	provider.mode = "normal"
	desired := coverageRecord("recover.example.com")
	recovered, err := app.upsertDNSWithRecovery(ctx, app.cloudflareProvider("coverage-token-abcdefghijklmnopqrstuvwxyz"), cloudflareZone("zone-coverage"), desired)
	if err != nil || recovered.ID == "" {
		t.Fatalf("DNS upsert recovery: %#v %v", recovered, err)
	}

	missingUserJob := jobs.Job{Payload: map[string]interface{}{"user_id": "missing-user", "operation_id": "missing-operation"}}
	if err := app.deleteUserExternal(ctx, missingUserJob); err != nil {
		t.Fatal(err)
	}
	activeUserJob := jobs.Job{Payload: map[string]interface{}{"user_id": fixture.client.UserID, "operation_id": "operation"}}
	if err := app.deleteUserExternal(ctx, activeUserJob); err == nil {
		t.Fatal("active user deletion job was accepted")
	}

	app.Config.ACMEEnabled = true
	app.ACMEProvider = coverageACMEProvider{}
	certificateMapping, err := app.CreateMapping(ctx, fixture.client, MappingRequest{Name: "acme-http", ProxyType: "http", LocalIP: "127.0.0.1", LocalPort: 8131}, "jobs-acme-map-000001")
	if err != nil {
		t.Fatal(err)
	}
	certificateDomain, err := app.CreateDomain(ctx, fixture.client, DomainRequest{MappingID: certificateMapping.ID, Hostname: "acme.example.com", HTTPSMode: "auto_certificate"}, "jobs-acme-domain-000001")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.ExecContext(ctx, `INSERT OR IGNORE INTO certificates(id,domain_binding_id,provider,status,updated_at) VALUES(?,?,?,?,?)`, "certificate-coverage", certificateDomain.ID, "acme", "pending", nowString()); err != nil {
		t.Fatal(err)
	}
	if err := app.issueCertificate(ctx, jobs.Job{Payload: map[string]interface{}{"user_id": fixture.client.UserID, "domain_id": certificateDomain.ID}}); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.QueryRowContext(ctx, `SELECT status FROM certificates WHERE domain_binding_id=?`, certificateDomain.ID).Scan(&status); err != nil || status != "valid" {
		t.Fatalf("ACME certificate status=%q err=%v", status, err)
	}
	if _, err := app.DB.ExecContext(ctx, `INSERT INTO certificates(id,domain_binding_id,provider,status,updated_at) VALUES(?,?,?,?,?)`, "certificate-seed", checkDomain.ID, "acme", "pending", nowString()); err != nil {
		// The existing check domain has no ACME certificate yet, so this is the
		// restart-seeding path for a pending certificate.
		t.Fatal(err)
	}
	if err := app.seedPendingJobs(ctx); err != nil {
		t.Fatal(err)
	}
	if err := app.issueCertificate(ctx, jobs.Job{Payload: map[string]interface{}{"user_id": fixture.client.UserID, "domain_id": "missing-domain"}}); err != nil {
		t.Fatal(err)
	}

}

func TestRunJobsSeedsAndStopsOnCancellation(t *testing.T) {
	fixture := newServiceCoverageFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	if err := fixture.app.RunJobs(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("RunJobs cancellation error=%v", err)
	}
}

func coverageRecord(name string) cloudflare.Record {
	return cloudflare.Record{ID: "recovered", Type: "CNAME", Name: name, Content: "frp.example.com", TTL: 300}
}

func cloudflareZone(id string) cloudflare.Zone {
	return cloudflare.Zone{ID: id, Name: "example.com"}
}
