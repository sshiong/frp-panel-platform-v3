package service

import (
	"context"
	"errors"
	"testing"

	"github.com/ricardo/frp-panel-platform/server/internal/jobs"
)

func drainDueJobs(t *testing.T, app *App) {
	t.Helper()
	for {
		job, err := app.Jobs.Claim(context.Background())
		if errors.Is(err, jobs.ErrNoJob) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := app.Jobs.Complete(context.Background(), job.ID); err != nil {
			t.Fatal(err)
		}
	}
}

func TestManagedDNSSyncIsExplicitAndDoesNotAdoptUnmanagedRecords(t *testing.T) {
	app, database, _, user := newUserDeletionFixture(t)
	mapping, err := app.CreateMapping(context.Background(), user, MappingRequest{Name: "dns-sync", ProxyType: "http", LocalIP: "127.0.0.1", LocalPort: 8080}, "dns-sync-map-123456")
	if err != nil {
		t.Fatal(err)
	}
	domain, err := app.CreateDomain(context.Background(), user, DomainRequest{MappingID: mapping.ID, Hostname: "managed.example.com", HTTPSMode: "http_only"}, "dns-sync-domain-123456")
	if err != nil {
		t.Fatal(err)
	}
	drainDueJobs(t, app)
	if _, err := database.Exec(`UPDATE dns_records SET managed_by_panel=1,adopted=0,sync_status='synced' WHERE domain_binding_id=?`, domain.ID); err != nil {
		t.Fatal(err)
	}
	if err := app.ResolveDomainDNS(context.Background(), user, domain.ID, "sync", "dns-sync-action-123456"); err != nil {
		t.Fatal(err)
	}
	job, err := app.Jobs.Claim(context.Background())
	if err != nil || job.Type != "domain_dns_sync" || job.Payload["action"] != "sync" {
		t.Fatalf("managed DNS sync was not queued: %#v %v", job, err)
	}
	if err := app.Jobs.Complete(context.Background(), job.ID); err != nil {
		t.Fatal(err)
	}
	var operationType string
	if err := database.QueryRow(`SELECT operation_type FROM operations WHERE resource_id=? ORDER BY created_at DESC LIMIT 1`, domain.ID).Scan(&operationType); err != nil {
		t.Fatal(err)
	}
	if operationType != "dns_sync" {
		t.Fatalf("unexpected DNS sync operation type: %q", operationType)
	}

	otherMapping, err := app.CreateMapping(context.Background(), user, MappingRequest{Name: "dns-unmanaged", ProxyType: "http", LocalIP: "127.0.0.1", LocalPort: 8081}, "dns-unmanaged-map-123456")
	if err != nil {
		t.Fatal(err)
	}
	unmanaged, err := app.CreateDomain(context.Background(), user, DomainRequest{MappingID: otherMapping.ID, Hostname: "unmanaged.example.com", HTTPSMode: "http_only"}, "dns-unmanaged-domain-123456")
	if err != nil {
		t.Fatal(err)
	}
	drainDueJobs(t, app)
	if err := app.ResolveDomainDNS(context.Background(), user, unmanaged.ID, "sync", "dns-unmanaged-action-123456"); err == nil {
		t.Fatal("sync unexpectedly accepted an unmanaged DNS record")
	}
}
