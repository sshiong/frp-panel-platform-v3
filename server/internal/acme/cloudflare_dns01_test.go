package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	internalcrypto "github.com/ricardo/frp-panel-platform/server/internal/crypto"
)

func TestWaitTXTUsesInjectedResolverForPropagation(t *testing.T) {
	called := false
	err := waitTXT(context.Background(), "_acme-challenge.example.com", "expected-value", time.Second, func(_ context.Context, name string) ([]string, error) {
		called = true
		if name != "_acme-challenge.example.com" {
			t.Fatalf("lookup name=%q", name)
		}
		return []string{"other", "expected-value"}, nil
	})
	if err != nil || !called {
		t.Fatalf("injected DNS propagation lookup failed: called=%v err=%v", called, err)
	}
}

type failingRoundTripper func(*http.Request) (*http.Response, error)

func (f failingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestIssueDNS01StopsWhenACMEOrderCannotBeCreated(t *testing.T) {
	root := t.TempDir()
	accountPath := filepath.Join(root, "account.key")
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
	ciphertext, nonce, err := internalcrypto.EncryptWithKey(wrappingKey, encoded, "acme-account:v1")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(accountPath, append(nonce, ciphertext...), 0o600); err != nil {
		t.Fatal(err)
	}

	provider, err := NewCloudflareDNS01(CloudflareDNS01Config{
		DirectoryURL:   "https://acme.example.test/directory",
		Email:          "ops@example.test",
		AccountKeyPath: accountPath,
		HTTPClient: &http.Client{Transport: failingRoundTripper(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("ACME directory unavailable")
		})},
	}, wrappingKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.IssueDNS01(context.Background(), "example.com"); err == nil {
		t.Fatal("expected ACME order failure")
	}
}
