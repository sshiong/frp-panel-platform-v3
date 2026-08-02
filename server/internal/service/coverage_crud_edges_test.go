package service

import (
	"context"
	"errors"
	"testing"
)

func TestServiceCoverageCRUDConflictAndIdempotencyEdges(t *testing.T) {
	fixture := newServiceCoverageFixture(t)
	ctx := context.Background()
	app, client, admin := fixture.app, fixture.client, fixture.admin

	wrongVersion := int64(999)
	if _, err := app.CreateMapping(ctx, client, MappingRequest{Name: "wrong-version", ProxyType: "tcp", LocalIP: "127.0.0.1", LocalPort: 8200, ExpectedConfigVersion: &wrongVersion}, "crud-map-conflict"); !errors.Is(err, ErrConfigConflict) {
		t.Fatalf("mapping config conflict: %v", err)
	}
	if _, err := app.CreateMapping(ctx, AuthContext{UserID: "missing-user", Role: "user", Generation: 1}, MappingRequest{Name: "missing-user", ProxyType: "tcp", LocalIP: "127.0.0.1", LocalPort: 8201}, "crud-map-missing-user"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("missing user mapping: %v", err)
	}

	remotePort := 6100
	mapping, err := app.CreateMapping(ctx, client, MappingRequest{Name: "crud-mapping", ProxyType: "tcp", LocalIP: "127.0.0.1", LocalPort: 8202, RemotePort: &remotePort}, "crud-map-create")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.CreateMapping(ctx, client, MappingRequest{Name: "reserved-port", ProxyType: "tcp", LocalIP: "127.0.0.1", LocalPort: 8203, RemotePort: &remotePort}, "crud-map-reserved"); !errors.Is(err, ErrPortReserved) {
		t.Fatalf("reserved remote port: %v", err)
	}

	missingRequest := MappingRequest{Name: "missing", ProxyType: "tcp", LocalIP: "127.0.0.1", LocalPort: 8204}
	if _, err := app.UpdateMapping(ctx, client, "missing-mapping", missingRequest, "crud-update-missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing mapping update: %v", err)
	}
	if _, err := app.UpdateMapping(ctx, client, mapping.ID, MappingRequest{Name: "conflict", ProxyType: "tcp", LocalIP: "127.0.0.1", LocalPort: 8205, ExpectedConfigVersion: &wrongVersion}, "crud-update-conflict"); !errors.Is(err, ErrConfigConflict) {
		t.Fatalf("mapping update config conflict: %v", err)
	}
	if _, err := app.UpdateMapping(ctx, client, "missing-mapping", MappingRequest{}, "crud-update-invalid"); err == nil {
		t.Fatal("invalid mapping update was accepted")
	}
	wrongRevision := mapping.Revision + 10
	if _, err := app.UpdateMapping(ctx, client, mapping.ID, MappingRequest{Name: "revision-conflict", ProxyType: "tcp", LocalIP: "127.0.0.1", LocalPort: 8206, ExpectedRevision: &wrongRevision}, "crud-update-revision-2"); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("mapping update revision conflict: %v", err)
	}
	badPort := 7000
	if _, err := app.UpdateMapping(ctx, client, mapping.ID, MappingRequest{Name: "bad-port", ProxyType: "tcp", LocalIP: "127.0.0.1", LocalPort: 8207, RemotePort: &badPort}, "crud-update-port"); err == nil {
		t.Fatal("out-of-range mapping update was accepted")
	}

	updatedRequest := MappingRequest{Name: "crud-mapping-updated", ProxyType: "tcp", LocalIP: "127.0.0.1", LocalPort: 8208, RemotePort: &remotePort}
	updated, err := app.UpdateMapping(ctx, client, mapping.ID, updatedRequest, "crud-update-success")
	if err != nil {
		t.Fatal(err)
	}
	if replay, err := app.UpdateMapping(ctx, client, mapping.ID, updatedRequest, "crud-update-success"); err != nil || replay.ID != updated.ID {
		t.Fatalf("mapping update replay: %#v %v", replay, err)
	}
	if _, err := app.UpdateMapping(ctx, client, mapping.ID, MappingRequest{Name: "reused", ProxyType: "tcp", LocalIP: "127.0.0.1", LocalPort: 8209, RemotePort: &remotePort}, "crud-update-success"); !errors.Is(err, ErrIdempotencyReuse) {
		t.Fatalf("mapping update idempotency reuse: %v", err)
	}

	if err := app.ToggleMapping(ctx, client, "missing-mapping", true, ToggleMappingOptions{IdempotencyKey: "crud-toggle-missing"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing toggle: %v", err)
	}
	if err := app.ToggleMapping(ctx, client, mapping.ID, true, ToggleMappingOptions{ExpectedConfigVersion: &wrongVersion, IdempotencyKey: "crud-toggle-version"}); !errors.Is(err, ErrConfigConflict) {
		t.Fatalf("toggle config conflict: %v", err)
	}
	wrongRevision = updated.Revision + 10
	if err := app.ToggleMapping(ctx, client, mapping.ID, true, ToggleMappingOptions{ExpectedRevision: &wrongRevision, IdempotencyKey: "crud-toggle-revision"}); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("toggle revision conflict: %v", err)
	}
	if err := app.ToggleMapping(ctx, client, mapping.ID, false, ToggleMappingOptions{IdempotencyKey: "crud-toggle-success"}); err != nil {
		t.Fatal(err)
	}
	if err := app.ToggleMapping(ctx, client, mapping.ID, false, ToggleMappingOptions{IdempotencyKey: "crud-toggle-success"}); err != nil {
		t.Fatal(err)
	}
	if err := app.ToggleMapping(ctx, client, mapping.ID, true, ToggleMappingOptions{IdempotencyKey: "crud-toggle-success"}); !errors.Is(err, ErrIdempotencyReuse) {
		t.Fatalf("toggle idempotency reuse: %v", err)
	}

	if _, err := app.DeleteMapping(ctx, client, "missing-mapping", false, "crud-delete-missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing mapping delete: %v", err)
	}
	deleteMapping, err := app.CreateMapping(ctx, client, MappingRequest{Name: "delete-mapping", ProxyType: "tcp", LocalIP: "127.0.0.1", LocalPort: 8210}, "crud-delete-create")
	if err != nil {
		t.Fatal(err)
	}
	operationID, err := app.DeleteMapping(ctx, client, deleteMapping.ID, false, "crud-delete-success")
	if err != nil || operationID == "" {
		t.Fatalf("mapping delete: %q %v", operationID, err)
	}
	if replay, err := app.DeleteMapping(ctx, client, deleteMapping.ID, false, "crud-delete-success"); err != nil || replay != operationID {
		t.Fatalf("mapping delete replay: %q %v", replay, err)
	}
	if _, err := app.DeleteMapping(ctx, client, deleteMapping.ID, true, "crud-delete-success"); !errors.Is(err, ErrIdempotencyReuse) {
		t.Fatalf("mapping delete idempotency reuse: %v", err)
	}

	if _, err := app.CreateDomain(ctx, client, DomainRequest{MappingID: mapping.ID, Hostname: "bad-mode.example.com", HTTPSMode: "invalid"}, "crud-domain-mode"); err == nil {
		t.Fatal("invalid HTTPS mode was accepted")
	}
	httpMapping, err := app.CreateMapping(ctx, client, MappingRequest{Name: "crud-http", ProxyType: "http", LocalIP: "127.0.0.1", LocalPort: 8211}, "crud-http-create")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.CreateDomain(ctx, client, DomainRequest{MappingID: httpMapping.ID, Hostname: "bad-dns.example.com", HTTPSMode: "http_only", DNSRecordType: "A", DNSContent: "not-an-ip"}, "crud-domain-dns"); err == nil {
		t.Fatal("invalid DNS content was accepted")
	}
	if _, err := app.CreateDomain(ctx, client, DomainRequest{MappingID: httpMapping.ID, Hostname: "conflict.example.com", HTTPSMode: "http_only", ExpectedConfigVersion: &wrongVersion}, "crud-domain-conflict"); !errors.Is(err, ErrConfigConflict) {
		t.Fatalf("domain config conflict: %v", err)
	}
	domainRequest := DomainRequest{MappingID: httpMapping.ID, Hostname: "Crud.Example.com", HTTPSMode: "http_only"}
	domain, err := app.CreateDomain(ctx, client, domainRequest, "crud-domain-success")
	if err != nil {
		t.Fatal(err)
	}
	if replay, err := app.CreateDomain(ctx, client, domainRequest, "crud-domain-success"); err != nil || replay.ID != domain.ID {
		t.Fatalf("domain replay: %#v %v", replay, err)
	}
	if _, err := app.CreateDomain(ctx, client, DomainRequest{MappingID: httpMapping.ID, Hostname: "crud.example.com", HTTPSMode: "http_only"}, "crud-domain-success"); !errors.Is(err, ErrIdempotencyReuse) {
		t.Fatalf("domain idempotency reuse: %v", err)
	}
	if _, err := app.CreateDomain(ctx, client, DomainRequest{MappingID: httpMapping.ID, Hostname: "CRUD.example.com", HTTPSMode: "http_only"}, "crud-domain-duplicate"); err == nil {
		t.Fatal("duplicate domain was accepted")
	}

	if err := app.ResolveDomainDNS(ctx, client, domain.ID, "unknown", "crud-dns-invalid"); err == nil {
		t.Fatal("invalid DNS action was accepted")
	}
	if err := app.ResolveDomainDNS(ctx, client, "missing-domain", "adopt", "crud-dns-missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing DNS action: %v", err)
	}
	if err := app.ResolveDomainDNS(ctx, client, domain.ID, "sync", "crud-dns-unmanaged"); err == nil {
		t.Fatal("unmanaged DNS record was synced")
	}
	if err := app.ResolveDomainDNS(ctx, client, domain.ID, "adopt", "crud-dns-adopt"); err != nil {
		t.Fatal(err)
	}
	if err := app.ResolveDomainDNS(ctx, client, domain.ID, "overwrite", "crud-dns-adopt"); !errors.Is(err, ErrIdempotencyReuse) {
		t.Fatalf("DNS action idempotency reuse: %v", err)
	}

	if _, err := app.DeleteDomain(ctx, client, "missing-domain", "crud-domain-delete-missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing domain delete: %v", err)
	}
	deleteDomain, err := app.CreateDomain(ctx, client, DomainRequest{MappingID: httpMapping.ID, Hostname: "delete.crud.example.com", HTTPSMode: "http_only"}, "crud-domain-delete-create")
	if err != nil {
		t.Fatal(err)
	}
	deleteOperation, err := app.DeleteDomain(ctx, client, deleteDomain.ID, "crud-domain-delete-success")
	if err != nil || deleteOperation == "" {
		t.Fatalf("domain delete: %q %v", deleteOperation, err)
	}
	if replay, err := app.DeleteDomain(ctx, client, deleteDomain.ID, "crud-domain-delete-success"); err != nil || replay != deleteOperation {
		t.Fatalf("domain delete replay: %q %v", replay, err)
	}

	snapshot, err := app.FullConfig(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.ApplyResult(ctx, client, ApplyResultRequest{Status: "unknown", ConfigVersion: snapshot.ConfigVersion}); err == nil {
		t.Fatal("invalid apply status was accepted")
	}
	if err := app.ApplyResult(ctx, client, ApplyResultRequest{Status: "failed", ConfigVersion: snapshot.ConfigVersion + 1, ErrorCode: "CONFLICT"}); !errors.Is(err, ErrConfigConflict) {
		t.Fatalf("apply version conflict: %v", err)
	}
	if err := app.ApplyResult(ctx, client, ApplyResultRequest{Status: "failed", ConfigVersion: snapshot.ConfigVersion, ErrorCode: "CONFIG_ERROR", ErrorMessage: "client rejected config"}); err != nil {
		t.Fatal(err)
	}

	if _, _, err := app.CreateUser(ctx, client, "should-fail"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("non-admin create user: %v", err)
	}
	if _, _, err := app.CreateUser(ctx, admin, "admin"); err == nil {
		t.Fatal("reserved admin username was accepted")
	}
	if _, _, err := app.CreateUser(ctx, admin, fixture.user.Username); err == nil {
		t.Fatal("duplicate username was accepted")
	}
	if err := app.SetUserStatus(ctx, admin, fixture.user.ID, "unknown"); err == nil {
		t.Fatal("invalid user status was accepted")
	}
	if err := app.SetUserStatus(ctx, admin, "missing-user", "active"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing user status: %v", err)
	}
	if _, err := app.ResetUserPassword(ctx, client, fixture.user.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("non-admin password reset: %v", err)
	}
	if _, err := app.ResetUserPassword(ctx, admin, "missing-user"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing password reset: %v", err)
	}
	if status, err := app.CloudflareStatus(ctx, "missing-user"); err != nil || status["configured"] != false {
		t.Fatalf("missing Cloudflare status: %#v %v", status, err)
	}
	if _, err := app.ResetFRPCredential(ctx, client, admin.UserID, fixture.password, "crud-frp-user-target"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("user FRP reset of another user: %v", err)
	}
	if _, err := app.ResetFRPCredential(ctx, client, "", "", "crud-frp-empty"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("empty FRP reset password: %v", err)
	}
	if _, err := app.ResetFRPCredential(ctx, admin, "", fixture.app.Config.AdminPassword, "crud-frp-admin-empty"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("admin FRP reset without target: %v", err)
	}
	if _, err := app.ResetFRPCredential(ctx, admin, admin.UserID, fixture.app.Config.AdminPassword, "crud-frp-admin-self"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("admin FRP reset of self: %v", err)
	}
	if _, err := app.ResetFRPCredential(ctx, admin, fixture.user.ID, "wrong-password", "crud-frp-wrong-password"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong FRP reset password: %v", err)
	}
	if _, err := app.ResetFRPCredential(ctx, admin, "missing-user", fixture.app.Config.AdminPassword, "crud-frp-missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing FRP reset target: %v", err)
	}
	if _, err := app.DeleteUser(ctx, admin, "missing-user", false, "crud-user-delete-missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing user deletion: %v", err)
	}
	if _, err := app.DeleteUser(ctx, admin, admin.UserID, false, "crud-user-delete-admin"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("admin deletion: %v", err)
	}
}
