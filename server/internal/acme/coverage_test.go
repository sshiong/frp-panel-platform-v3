package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ricardo/frp-panel-platform/server/internal/crypto"
	"golang.org/x/crypto/acme"
)

type coverageCertificateProvider struct{}

func (coverageCertificateProvider) IssueDNS01(context.Context, string) (Certificate, error) {
	return Certificate{CertPEM: []byte("certificate")}, nil
}

func TestACMEManagerAndDNS01Validation(t *testing.T) {
	if _, err := NewCloudflareDNS01(CloudflareDNS01Config{}, make([]byte, 31)); err == nil {
		t.Fatal("invalid ACME wrapping key was accepted")
	}
	if _, err := NewCloudflareDNS01(CloudflareDNS01Config{DirectoryURL: "https://acme.example.test", Email: "ops@example.test"}, make([]byte, 32)); err == nil {
		t.Fatal("incomplete ACME account path was accepted")
	}
	provider, err := NewCloudflareDNS01(CloudflareDNS01Config{DirectoryURL: "https://acme.example.test", Email: "ops@example.test", AccountKeyPath: filepath.Join(t.TempDir(), "account.key")}, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if provider.config.HTTPClient == nil || provider.config.Propagation <= 0 || provider.config.ClockTolerance <= 0 {
		t.Fatalf("ACME defaults not installed: %#v", provider.config)
	}
	if _, err := (Manager{}).IssueDNS01(context.Background(), "example.com"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("disabled ACME manager error=%v", err)
	}
	manager := Manager{Enabled: true, Provider: coverageCertificateProvider{}}
	if _, err := manager.IssueDNS01(context.Background(), ""); err == nil {
		t.Fatal("empty ACME domain was accepted")
	}
	if certificate, err := manager.IssueDNS01(context.Background(), "example.com"); err != nil || string(certificate.CertPEM) != "certificate" {
		t.Fatalf("provider certificate was not returned: %#v %v", certificate, err)
	}

	if _, err := dnsChallenge(nil); err == nil {
		t.Fatal("missing DNS challenge was accepted")
	}
	challenge, err := dnsChallenge([]*acme.Challenge{{Type: "http-01"}, {Type: "dns-01"}})
	if err != nil || challenge.Type != "dns-01" {
		t.Fatalf("DNS challenge selection failed: %#v %v", challenge, err)
	}
	if token, ok := CloudflareToken(WithCloudflareToken(context.Background(), "token")); !ok || token != "token" {
		t.Fatalf("Cloudflare context token missing: %q %v", token, ok)
	}
	if _, ok := CloudflareToken(context.Background()); ok {
		t.Fatal("empty Cloudflare context token unexpectedly present")
	}

	if err := waitTXT(context.Background(), "_acme-challenge.example.com", "expected", 0, func(context.Context, string) ([]string, error) { return nil, nil }); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("TXT timeout was not reported: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitTXT(ctx, "_acme-challenge.example.com", "expected", time.Minute, func(context.Context, string) ([]string, error) { return nil, errors.New("resolver unavailable") }); !errors.Is(err, context.Canceled) {
		t.Fatalf("TXT cancellation was not propagated: %v", err)
	}
}

func TestACMEStoredAccountAndProviderZoneLookup(t *testing.T) {
	root := t.TempDir()
	accountPath := filepath.Join(root, "nested", "account.key")
	wrappingKey := []byte("01234567890123456789012345678901")
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(accountKey)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(accountState{AccountURI: "https://acme.example.test/acct/1", KeyDER: keyDER})
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, nonce, err := crypto.EncryptWithKey(wrappingKey, encoded, "acme-account:v1")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(accountPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(accountPath, append(nonce, ciphertext...), 0o600); err != nil {
		t.Fatal(err)
	}
	provider, err := NewCloudflareDNS01(CloudflareDNS01Config{DirectoryURL: "https://acme.example.test", Email: "ops@example.test", AccountKeyPath: accountPath}, wrappingKey)
	if err != nil {
		t.Fatal(err)
	}
	material, err := provider.loadOrRegisterAccount(context.Background())
	if err != nil || material.uri != "https://acme.example.test/acct/1" || material.key == nil {
		t.Fatalf("stored ACME account was not loaded: %#v %v", material, err)
	}
	if err := os.WriteFile(accountPath, []byte("bad"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.loadOrRegisterAccount(context.Background()); err == nil {
		t.Fatal("malformed stored ACME account was accepted")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/zones" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"success":true,"result":[{"id":"zone-1","name":"example.com"}],"result_info":{"page":1,"total_pages":1}}`)
	}))
	defer server.Close()
	provider.config.CloudflareURL = server.URL
	provider.config.HTTPClient = server.Client()
	if _, _, err := provider.providerAndZone(context.Background(), "example.com"); err == nil {
		t.Fatal("provider lookup without Cloudflare token was accepted")
	}
	zoneProvider, zone, err := provider.providerAndZone(WithCloudflareToken(context.Background(), "token"), "api.example.com")
	if err != nil || zone.ID != "zone-1" || zoneProvider == nil {
		t.Fatalf("Cloudflare zone lookup failed: %#v %#v %v", zoneProvider, zone, err)
	}
	if _, _, err := provider.providerAndZone(WithCloudflareToken(context.Background(), "token"), "api.other.test"); err == nil {
		t.Fatal("unmatched Cloudflare zone was accepted")
	}
}
