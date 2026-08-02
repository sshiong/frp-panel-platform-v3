package service

import (
	"context"
	"errors"
	"testing"
)

func TestServiceCoverageAuthenticationAndValidationEdges(t *testing.T) {
	fixture := newServiceCoverageFixture(t)
	ctx := context.Background()
	app := fixture.app

	if !ValidateCSRF(fixture.admin, fixture.adminLogin.CSRFToken) {
		t.Fatal("the CSRF token issued for the admin session should verify")
	}
	if ValidateCSRF(fixture.admin, "wrong-csrf-token") || ValidateCSRF(fixture.admin, "") {
		t.Fatal("invalid CSRF tokens must fail closed")
	}
	if _, err := app.Login(ctx, "", fixture.app.Config.AdminPassword, "admin_panel", "", ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("empty username error=%v", err)
	}
	if _, err := app.Login(ctx, "admin", "short", "admin_panel", "", ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("short password error=%v", err)
	}
	if _, err := app.Login(ctx, "admin", "wrong-password-2026!", "admin_panel", "", ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password error=%v", err)
	}
	if _, err := app.Login(ctx, "admin", fixture.app.Config.AdminPassword, "client_panel", "", ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("admin client-panel login error=%v", err)
	}
	if _, err := app.Login(ctx, fixture.client.Username, fixture.password, "admin_panel", "", ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("user admin-panel login error=%v", err)
	}
	if _, err := app.Authenticate(ctx, ""); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("empty bearer error=%v", err)
	}
	if _, err := app.Authenticate(ctx, "Bearer "); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("empty bearer prefix error=%v", err)
	}
	if _, err := app.Authenticate(ctx, "not-a-session"); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("unknown session error=%v", err)
	}

	if _, _, err := app.IssueReauthTicket(ctx, fixture.admin, ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("empty reauth password error=%v", err)
	}
	if _, _, err := app.IssueReauthTicket(ctx, fixture.admin, "wrong-password-2026!"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong reauth password error=%v", err)
	}
	ticket, _, err := app.IssueReauthTicket(ctx, fixture.admin, fixture.app.Config.AdminPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.RequireReauthTicket(ctx, fixture.admin, ""); !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("empty reauth ticket error=%v", err)
	}
	if err := app.RequireReauthTicket(ctx, fixture.admin, "wrong-ticket"); !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("wrong reauth ticket error=%v", err)
	}
	if err := app.RequireReauthTicket(ctx, fixture.admin, ticket); err != nil {
		t.Fatal(err)
	}

	if err := app.ChangeCredentials(ctx, fixture.admin, fixture.app.Config.AdminPassword, "", "short"); err == nil {
		t.Fatal("short replacement password was accepted")
	}
	if err := app.ChangeCredentials(ctx, fixture.admin, fixture.app.Config.AdminPassword, "bad name", "Admin-Password-2027!"); err == nil {
		t.Fatal("invalid administrator username was accepted")
	}
	if err := app.ChangeCredentials(ctx, fixture.client, fixture.password, "renamed-user", "Client-Password-2027!"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("non-admin username change error=%v", err)
	}
	if err := app.ChangeCredentials(ctx, fixture.client, "wrong-password", "", "Client-Password-2027!"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong current password error=%v", err)
	}
	if err := app.ChangeCredentials(ctx, fixture.client, fixture.password, "", "Client-Password-2027!"); err != nil {
		t.Fatal(err)
	}
	if err := app.ChangeCredentials(ctx, fixture.client, fixture.password, "", "Client-Password-2028!"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("old client password remained valid: %v", err)
	}

	if _, err := app.AdminUsers(ctx); err != nil {
		t.Fatal(err)
	}
	if err := app.Logout(ctx, fixture.admin, "coverage-auth-edge"); err != nil {
		t.Fatal(err)
	}
	if _, err := app.Authenticate(ctx, fixture.adminLogin.Token); err == nil {
		t.Fatal("logged-out administrator session remained valid")
	}
	if err := app.TouchSession(ctx, fixture.admin); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("logged-out session was touchable: %v", err)
	}
}

func TestServiceCoveragePureValidationAndPortLeaseEdges(t *testing.T) {
	fixture := newServiceCoverageFixture(t)
	ctx := context.Background()

	invalidMappings := []MappingRequest{
		{Name: "", ProxyType: "tcp", LocalIP: "127.0.0.1", LocalPort: 1},
		{Name: "ok", ProxyType: "sctp", LocalIP: "127.0.0.1", LocalPort: 1},
		{Name: "ok", ProxyType: "tcp", LocalIP: "not a host", LocalPort: 1},
		{Name: "ok", ProxyType: "tcp", LocalIP: "127.0.0.1", LocalPort: 0},
		{Name: "ok", ProxyType: "tcp", LocalIP: "127.0.0.1", LocalPort: 65536},
	}
	for _, request := range invalidMappings {
		if err := validateMapping(request); err == nil {
			t.Fatalf("invalid mapping passed validation: %#v", request)
		}
	}
	remotePort := -1
	if err := validateMapping(MappingRequest{Name: "ok", ProxyType: "tcp", LocalIP: "127.0.0.1", LocalPort: 1, RemotePort: &remotePort}); err == nil {
		t.Fatal("negative remote port passed validation")
	}
	remotePort = 65536
	if err := validateMapping(MappingRequest{Name: "ok", ProxyType: "tcp", LocalIP: "127.0.0.1", LocalPort: 1, RemotePort: &remotePort}); err == nil {
		t.Fatal("out-of-range remote port passed validation")
	}

	if recordType, content, ttl, proxied, err := normalizeDNSIntent("frp.example.com", DomainRequest{HTTPSMode: "cloudflare_proxy"}); err != nil || recordType != "CNAME" || content != "frp.example.com" || ttl != 300 || !proxied {
		t.Fatalf("default DNS intent: type=%q content=%q ttl=%d proxied=%v err=%v", recordType, content, ttl, proxied, err)
	}
	if recordType, content, _, _, err := normalizeDNSIntent("", DomainRequest{DNSRecordType: "A", DNSContent: "192.0.2.10", DNSTTL: 60}); err != nil || recordType != "A" || content != "192.0.2.10" {
		t.Fatalf("A DNS intent: type=%q content=%q err=%v", recordType, content, err)
	}
	if recordType, content, _, _, err := normalizeDNSIntent("", DomainRequest{DNSRecordType: "AAAA", DNSContent: "2001:db8::10", DNSTTL: 86400}); err != nil || recordType != "AAAA" || content != "2001:db8::10" {
		t.Fatalf("AAAA DNS intent: type=%q content=%q err=%v", recordType, content, err)
	}
	invalidDNS := []DomainRequest{
		{DNSRecordType: "TXT"},
		{DNSRecordType: "A", DNSContent: "2001:db8::1"},
		{DNSRecordType: "AAAA", DNSContent: "192.0.2.1"},
		{DNSRecordType: "CNAME", DNSContent: "bad"},
		{DNSRecordType: "CNAME", DNSTTL: 59},
		{DNSRecordType: "CNAME", DNSTTL: 86401},
	}
	for _, request := range invalidDNS {
		if _, _, _, _, err := normalizeDNSIntent("frp.example.com", request); err == nil {
			t.Fatalf("invalid DNS intent passed validation: %#v", request)
		}
	}
	for _, domain := range []string{"", "localhost", "-bad.example.com", "bad-.example.com", "bad\\example.com", "bad/example.com"} {
		if _, err := normalizeDomain(domain); err == nil {
			t.Fatalf("invalid domain passed normalization: %q", domain)
		}
	}
	if page, size := normalizePage(0, 0); page != 1 || size != 50 {
		t.Fatalf("default pagination=%d/%d", page, size)
	}
	if page, size := normalizePage(2, 1000); page != 2 || size != 200 {
		t.Fatalf("bounded pagination=%d/%d", page, size)
	}
	if got := safeError("  line1\nline2\r\n" + string(make([]byte, 250))); len(got) != 240 || got == "" {
		t.Fatalf("safeError did not sanitize/truncate: len=%d", len(got))
	}
	if shortID("12345678901234567890") != "123456789012" || shortID("short") != "short" {
		t.Fatal("shortID boundaries are incorrect")
	}
	if allowedAuditField("not-allowed") || !allowedAuditField("provider") || validUsername("1bad") || validUsername("a") {
		t.Fatal("audit field or username validation boundaries are incorrect")
	}

	mapping, err := fixture.app.CreateMapping(ctx, fixture.client, MappingRequest{Name: "lease-edge", ProxyType: "tcp", LocalIP: "127.0.0.1", LocalPort: 8099, RemotePort: ptrInt(6000)}, "lease-edge-mapping-000001")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := fixture.database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := allocatePort(ctx, tx, 6000, 6000); err == nil {
		// The port is already leased by the mapping, so the allocator must
		// report the exhausted one-port range.
		t.Fatal("the allocator returned an already leased port")
	}
	_ = tx.Rollback()
	_ = mapping
	if _, err := fixture.app.CreateMapping(ctx, fixture.client, MappingRequest{Name: "no-port", ProxyType: "tcp", LocalIP: "127.0.0.1", LocalPort: 8100}, "lease-edge-no-port-000001"); err != nil {
		// The fixture has a broad range; this assertion only ensures the
		// normal allocator path remains usable after the explicit lease.
		t.Fatal(err)
	}
	if nullablePort(nil) != nil || nullablePort(ptrInt(6001)) != 6001 || nullableString("") != nil || nullableString("x") != "x" || boolInt(false) != 0 || boolInt(true) != 1 {
		t.Fatal("nullable and boolean conversion helpers returned unexpected values")
	}
	token, err := randomToken()
	if err != nil || token == "" || requestHash(map[string]string{"x": "y"}) == "" || sha256Hex("x") == "" {
		t.Fatal("hash/token helpers returned an empty value")
	}
}

func TestServiceCoverageFRPAuthorizationBranches(t *testing.T) {
	fixture := newServiceCoverageFixture(t)
	ctx := context.Background()
	app := fixture.app

	if ok, code, _ := app.AuthorizeFRP(ctx, "Ping", fixture.clientLogin.FRPUsername, fixture.clientLogin.RuntimeCredential, fixture.client.Generation, "", 0, 0, ""); !ok || code != "" {
		t.Fatalf("compatibility FRP authorization failed: ok=%v code=%q", ok, code)
	}
	if ok, code, _ := app.AuthorizeFRPWithProxyType(ctx, "NewWorkConn", fixture.clientLogin.FRPUsername, fixture.clientLogin.RuntimeCredential, fixture.client.Generation, "", 0, 0, "", "tcp"); !ok || code != "" {
		t.Fatalf("proxy-type FRP authorization failed: ok=%v code=%q", ok, code)
	}
	for _, check := range []struct {
		name       string
		runtime    string
		generation int64
		secret     string
		code       string
	}{
		{name: "runtime", runtime: "wrong", generation: fixture.client.Generation, secret: fixture.clientLogin.FRPSecret, code: "FRP_RUNTIME_CREDENTIAL_INVALID"},
		{name: "generation", runtime: fixture.clientLogin.RuntimeCredential, generation: fixture.client.Generation + 1, secret: fixture.clientLogin.FRPSecret, code: "SESSION_GENERATION_MISMATCH"},
		{name: "secret", runtime: fixture.clientLogin.RuntimeCredential, generation: fixture.client.Generation, secret: "wrong-secret", code: "FRP_USER_CREDENTIAL_INVALID"},
		{name: "operation", runtime: fixture.clientLogin.RuntimeCredential, generation: fixture.client.Generation, secret: fixture.clientLogin.FRPSecret, code: "FRP_OPERATION_NOT_ALLOWED"},
	} {
		operation := "Ping"
		if check.name == "operation" {
			operation = "Unknown"
		}
		if ok, code, _ := app.AuthorizeFRPWithCredentials(ctx, operation, fixture.clientLogin.FRPUsername, check.runtime, check.secret, check.generation, "", 0, 0, "", ""); ok || code != check.code {
			t.Fatalf("%s FRP authorization: ok=%v code=%q want=%q", check.name, ok, code, check.code)
		}
	}

	httpMapping, err := app.CreateMapping(ctx, fixture.client, MappingRequest{Name: "frp-http", ProxyType: "http", LocalIP: "127.0.0.1", LocalPort: 8110}, "frp-auth-http-000001")
	if err != nil {
		t.Fatal(err)
	}
	domain, err := app.CreateDomain(ctx, fixture.client, DomainRequest{MappingID: httpMapping.ID, Hostname: "frp.example.com", HTTPSMode: "http_only"}, "frp-auth-domain-000001")
	if err != nil {
		t.Fatal(err)
	}
	if ok, code, _ := app.AuthorizeFRPWithCredentials(ctx, "NewProxy", fixture.clientLogin.FRPUsername, fixture.clientLogin.RuntimeCredential, fixture.clientLogin.FRPSecret, fixture.client.Generation, httpMapping.ID, httpMapping.Revision, 0, domain.Normalized, "http"); !ok || code != "" {
		t.Fatalf("valid HTTP proxy authorization: ok=%v code=%q", ok, code)
	}
	for _, check := range []struct {
		name, hostname, proxyType, code string
		revision, remotePort            int64
	}{
		{name: "mapping", hostname: domain.Normalized, proxyType: "http", revision: httpMapping.Revision, code: "MAPPING_NOT_FOUND"},
		{name: "proxy-type", hostname: domain.Normalized, proxyType: "tcp", revision: httpMapping.Revision, code: "PROXY_TYPE_NOT_ALLOWED"},
		{name: "revision", hostname: domain.Normalized, proxyType: "http", revision: httpMapping.Revision + 1, code: "RESOURCE_REVISION_CONFLICT"},
		{name: "domain", hostname: "other.example.com", proxyType: "http", revision: httpMapping.Revision, code: "DOMAIN_NOT_AUTHORIZED"},
		{name: "hostname", hostname: "bad", proxyType: "http", revision: httpMapping.Revision, code: "DOMAIN_NOT_AUTHORIZED"},
		{name: "required-domain", hostname: "", proxyType: "http", revision: httpMapping.Revision, code: "DOMAIN_REQUIRED"},
	} {
		mappingID := httpMapping.ID
		if check.name == "mapping" {
			mappingID = "missing-mapping"
		}
		if ok, code, _ := app.AuthorizeFRPWithCredentials(ctx, "NewProxy", fixture.clientLogin.FRPUsername, fixture.clientLogin.RuntimeCredential, fixture.clientLogin.FRPSecret, fixture.client.Generation, mappingID, check.revision, int(check.remotePort), check.hostname, check.proxyType); ok || code != check.code {
			t.Fatalf("%s FRP authorization: ok=%v code=%q want=%q", check.name, ok, code, check.code)
		}
	}
	if err := app.ToggleMapping(ctx, fixture.client, httpMapping.ID, false, ToggleMappingOptions{IdempotencyKey: "frp-auth-toggle-000001"}); err != nil {
		t.Fatal(err)
	}
	if ok, code, _ := app.AuthorizeFRPWithCredentials(ctx, "NewProxy", fixture.clientLogin.FRPUsername, fixture.clientLogin.RuntimeCredential, fixture.clientLogin.FRPSecret, fixture.client.Generation, httpMapping.ID, httpMapping.Revision, 0, domain.Normalized, "http"); ok || code != "MAPPING_NOT_AUTHORIZED" {
		t.Fatalf("disabled mapping authorization: ok=%v code=%q", ok, code)
	}
}

func ptrInt(value int) *int { return &value }
