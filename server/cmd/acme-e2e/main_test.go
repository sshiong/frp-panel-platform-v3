package main

import "testing"

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
