package service

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
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

type clearDuringACMEProvider struct {
	app      *App
	auth     AuthContext
	password string
	cleared  bool
}

func (p *clearDuringACMEProvider) IssueDNS01(_ context.Context, domain string) (acme.Certificate, error) {
	if !p.cleared {
		p.cleared = true
		if err := p.app.ClearCloudflareToken(context.Background(), p.auth, p.password); err != nil {
			return acme.Certificate{}, err
		}
	}
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
	if _, err := app.ActivateCloudflareToken(ctx, fixture.client, 1, false, ticket); err != nil {
		t.Fatalf("Cloudflare token activation: %v", err)
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

func TestCloudflareJobsBlockWhenTokenIsClearedDuringExternalWork(t *testing.T) {
	t.Run("token verification", func(t *testing.T) {
		fixture := newServiceCoverageFixture(t)
		ctx := context.Background()
		app := fixture.app
		app.Config.CloudflareAPIBaseURL = "https://api.example.test/client/v4"
		var transportCalls int
		cleared := false
		app.CloudflareHTTPClient = &http.Client{Transport: cloudflareRoundTripper(func(req *http.Request) (*http.Response, error) {
			transportCalls++
			if !cleared {
				cleared = true
				if err := app.ClearCloudflareToken(ctx, fixture.client, fixture.password); err != nil {
					return nil, err
				}
			}
			return (&jobsCoverageProvider{}).RoundTrip(req)
		})}
		ticket, _, err := app.IssueReauthTicket(ctx, fixture.client, fixture.password)
		if err != nil {
			t.Fatal(err)
		}
		if err := app.SaveCloudflareToken(ctx, fixture.client, "verification-token-abcdefghijklmnopqrstuvwxyz", ticket); err != nil {
			t.Fatal(err)
		}
		job, err := app.Jobs.Claim(ctx)
		if err != nil || job.Type != "cloudflare_token_verify" {
			t.Fatalf("Cloudflare token job=%#v err=%v", job, err)
		}
		err = app.handleJob(ctx, job)
		var blocked *jobs.BlockedError
		if !errors.As(err, &blocked) || !errors.Is(err, ErrCloudflareTokenInactive) {
			t.Fatalf("token verification was not blocked after clear: err=%v", err)
		}
		if transportCalls != 1 {
			t.Fatalf("stale token verification reached the provider after clear: transport calls=%d", transportCalls)
		}
		if err := app.Jobs.Block(ctx, job.ID, blocked); err != nil {
			t.Fatal(err)
		}
		var status string
		if err := app.DB.QueryRowContext(ctx, `SELECT status FROM cloudflare_credentials WHERE user_id=? ORDER BY token_version DESC LIMIT 1`, fixture.client.UserID).Scan(&status); err != nil {
			t.Fatal(err)
		}
		if status != "retired" {
			t.Fatalf("cleared verification credential status=%q", status)
		}
	})

	t.Run("activation", func(t *testing.T) {
		fixture := newServiceCoverageFixture(t)
		ctx := context.Background()
		app := fixture.app
		app.Config.CloudflareAPIBaseURL = "https://api.example.test/client/v4"
		app.CloudflareHTTPClient = &http.Client{Transport: &jobsCoverageProvider{}}
		ticket, _, err := app.IssueReauthTicket(ctx, fixture.client, fixture.password)
		if err != nil {
			t.Fatal(err)
		}
		if err := app.SaveCloudflareToken(ctx, fixture.client, "activation-token-abcdefghijklmnopqrstuvwxyz", ticket); err != nil {
			t.Fatal(err)
		}
		job, err := app.Jobs.Claim(ctx)
		if err != nil || job.Type != "cloudflare_token_verify" {
			t.Fatalf("Cloudflare token job=%#v err=%v", job, err)
		}
		if err := app.handleJob(ctx, job); err != nil {
			t.Fatal(err)
		}
		if err := app.Jobs.Complete(ctx, job.ID); err != nil {
			t.Fatal(err)
		}

		cleared := false
		transportCalls := 0
		app.CloudflareHTTPClient = &http.Client{Transport: cloudflareRoundTripper(func(req *http.Request) (*http.Response, error) {
			transportCalls++
			if !cleared {
				cleared = true
				if err := app.ClearCloudflareToken(ctx, fixture.client, fixture.password); err != nil {
					return nil, err
				}
			}
			return (&jobsCoverageProvider{}).RoundTrip(req)
		})}
		if _, err := app.ActivateCloudflareToken(ctx, fixture.client, 1, false, ticket); !errors.Is(err, ErrCloudflareTokenInactive) {
			t.Fatalf("activation was not stopped after clear: %v", err)
		}
		if transportCalls != 1 {
			t.Fatalf("stale activation reached the provider after clear: transport calls=%d", transportCalls)
		}
		var active sql.NullInt64
		if err := app.DB.QueryRowContext(ctx, `SELECT active_cloudflare_token_version FROM users WHERE id=?`, fixture.client.UserID).Scan(&active); err != nil {
			t.Fatal(err)
		}
		if active.Valid {
			t.Fatalf("cleared candidate became active: %v", active.Int64)
		}
	})

	t.Run("dns", func(t *testing.T) {
		fixture := newServiceCoverageFixture(t)
		ctx := context.Background()
		app := fixture.app
		provider := &jobsCoverageProvider{}
		app.CloudflareHTTPClient = &http.Client{Transport: provider}
		app.Config.CloudflareAPIBaseURL = "https://api.example.test/client/v4"
		activateCoverageCloudflareToken(t, fixture)

		mapping, err := app.CreateMapping(ctx, fixture.client, MappingRequest{Name: "clear-dns", ProxyType: "http", LocalIP: "127.0.0.1", LocalPort: 8170}, "clear-dns-map-000001")
		if err != nil {
			t.Fatal(err)
		}
		domain, err := app.CreateDomain(ctx, fixture.client, DomainRequest{MappingID: mapping.ID, Hostname: "clear-dns.example.com", HTTPSMode: "http_only"}, "clear-dns-domain-000001")
		if err != nil {
			t.Fatal(err)
		}

		cleared := false
		app.CloudflareHTTPClient = &http.Client{Transport: cloudflareRoundTripper(func(req *http.Request) (*http.Response, error) {
			if !cleared && req.Method == http.MethodGet && strings.TrimPrefix(req.URL.Path, "/client/v4") == "/zones" {
				cleared = true
				if err := app.ClearCloudflareToken(ctx, fixture.client, fixture.password); err != nil {
					return nil, err
				}
			}
			return provider.RoundTrip(req)
		})}
		err = app.syncDomainDNS(ctx, jobs.Job{Payload: map[string]interface{}{"user_id": fixture.client.UserID, "domain_id": domain.ID, "action": "check"}})
		var blocked *jobs.BlockedError
		if !errors.As(err, &blocked) || !errors.Is(err, ErrCloudflareTokenInactive) {
			t.Fatalf("DNS job was not blocked after clear: err=%v", err)
		}
		var dnsCount int
		if err := app.DB.QueryRowContext(ctx, `SELECT COUNT(1) FROM dns_records WHERE domain_binding_id=? AND managed_by_panel=1`, domain.ID).Scan(&dnsCount); err != nil {
			t.Fatal(err)
		}
		if dnsCount != 0 {
			t.Fatalf("stale DNS job persisted a local record: %d", dnsCount)
		}
	})

	t.Run("acme", func(t *testing.T) {
		fixture := newServiceCoverageFixture(t)
		ctx := context.Background()
		app := fixture.app
		app.CloudflareHTTPClient = &http.Client{Transport: &jobsCoverageProvider{}}
		app.Config.CloudflareAPIBaseURL = "https://api.example.test/client/v4"
		activateCoverageCloudflareToken(t, fixture)
		app.Config.ACMEEnabled = true
		app.ACMEProvider = &clearDuringACMEProvider{app: app, auth: fixture.client, password: fixture.password}

		mapping, err := app.CreateMapping(ctx, fixture.client, MappingRequest{Name: "clear-acme", ProxyType: "http", LocalIP: "127.0.0.1", LocalPort: 8171}, "clear-acme-map-000001")
		if err != nil {
			t.Fatal(err)
		}
		domain, err := app.CreateDomain(ctx, fixture.client, DomainRequest{MappingID: mapping.ID, Hostname: "clear-acme.example.com", HTTPSMode: "auto_certificate"}, "clear-acme-domain-000001")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := app.DB.ExecContext(ctx, `INSERT OR IGNORE INTO certificates(id,domain_binding_id,provider,status,updated_at) VALUES(?,?,?,?,?)`, "certificate-clear-acme", domain.ID, "acme", "pending", nowString()); err != nil {
			t.Fatal(err)
		}
		err = app.issueCertificate(ctx, jobs.Job{Payload: map[string]interface{}{"user_id": fixture.client.UserID, "domain_id": domain.ID}})
		var blocked *jobs.BlockedError
		if !errors.As(err, &blocked) || !errors.Is(err, ErrCloudflareTokenInactive) {
			t.Fatalf("ACME job was not blocked after clear: err=%v", err)
		}
		var status string
		if err := app.DB.QueryRowContext(ctx, `SELECT status FROM certificates WHERE domain_binding_id=?`, domain.ID).Scan(&status); err != nil {
			t.Fatal(err)
		}
		if status != "pending" {
			t.Fatalf("stale ACME job changed certificate status to %q", status)
		}
		if _, err := os.Stat(filepath.Join(app.Config.DataDir, "certificates", domain.ID, "cert.pem")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stale ACME job left certificate material: err=%v", err)
		}
	})
}

func activateCoverageCloudflareToken(t *testing.T, fixture serviceCoverageFixture) {
	t.Helper()
	ctx := context.Background()
	ticket, _, err := fixture.app.IssueReauthTicket(ctx, fixture.client, fixture.password)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.app.SaveCloudflareToken(ctx, fixture.client, "coverage-token-abcdefghijklmnopqrstuvwxyz", ticket); err != nil {
		t.Fatal(err)
	}
	tokenJob, err := fixture.app.Jobs.Claim(ctx)
	if err != nil || tokenJob.Type != "cloudflare_token_verify" {
		t.Fatalf("Cloudflare token job=%#v err=%v", tokenJob, err)
	}
	if err := fixture.app.handleJob(ctx, tokenJob); err != nil {
		t.Fatal(err)
	}
	if err := fixture.app.Jobs.Complete(ctx, tokenJob.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.app.ActivateCloudflareToken(ctx, fixture.client, 1, false, ticket); err != nil {
		t.Fatal(err)
	}
}

func coverageRecord(name string) cloudflare.Record {
	return cloudflare.Record{ID: "recovered", Type: "CNAME", Name: name, Content: "frp.example.com", TTL: 300}
}

func cloudflareZone(id string) cloudflare.Zone {
	return cloudflare.Zone{ID: id, Name: "example.com"}
}
