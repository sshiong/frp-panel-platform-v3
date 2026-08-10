package main

import (
	"strings"
	"testing"
)

func TestValidateStagingDirectory(t *testing.T) {
	tests := []struct {
		name string
		url  string
		ok   bool
	}{
		{name: "official endpoint", url: "https://acme-staging-v02.api.letsencrypt.org/directory", ok: true},
		{name: "production endpoint", url: "https://acme-v02.api.letsencrypt.org/directory"},
		{name: "staging substring on untrusted host", url: "https://acme-staging.evil.example/directory"},
		{name: "userinfo", url: "https://operator@acme-staging-v02.api.letsencrypt.org/directory"},
		{name: "alternate port", url: "https://acme-staging-v02.api.letsencrypt.org:8443/directory"},
		{name: "query string", url: "https://acme-staging-v02.api.letsencrypt.org/directory?redirect=https://example.test"},
		{name: "wrong path", url: "https://acme-staging-v02.api.letsencrypt.org/acme/directory"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateStagingDirectory(test.url)
			if test.ok && err != nil {
				t.Fatalf("valid staging URL rejected: %v", err)
			}
			if !test.ok && err == nil {
				t.Fatal("unsafe staging URL accepted")
			}
		})
	}
}

func TestHostnameInZone(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		zone     string
		want     bool
	}{
		{name: "subdomain", hostname: "a.example.com", zone: "example.com", want: true},
		{name: "case and trailing dot", hostname: "A.Example.Com.", zone: "example.com.", want: true},
		{name: "apex", hostname: "example.com", zone: "example.com", want: true},
		{name: "label boundary", hostname: "a.not-example.com", zone: "example.com", want: false},
		{name: "suffix attack", hostname: "example.com.evil.test", zone: "example.com", want: false},
		{name: "empty hostname", hostname: "", zone: "example.com", want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := hostnameInZone(test.hostname, test.zone); got != test.want {
				t.Fatalf("hostnameInZone(%q, %q) = %v, want %v", test.hostname, test.zone, got, test.want)
			}
		})
	}
}

func TestRunRejectsACMEDomainOutsideExpectedZone(t *testing.T) {
	t.Setenv("CLOUDFLARE_E2E_API_TOKEN", "sandbox-token")
	t.Setenv("FRP_ACME_E2E_DOMAIN", "outside.example.net")
	t.Setenv("FRP_ACME_E2E_EXPECTED_ZONE_NAME", "example.com")

	status, output := run()
	if status == 0 || !strings.Contains(output.Error, "outside expected Cloudflare Zone") {
		t.Fatalf("run accepted a cross-zone ACME domain: status=%d output=%#v", status, output)
	}
}
