package security

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestNormalizeServerURL(t *testing.T) {
	cases := map[string]string{"panel.example.com": "https://panel.example.com", "panel.example.com:8443": "https://panel.example.com:8443", "https://203.0.113.10": "https://203.0.113.10", "https://[2001:db8::1]:8443": "https://[2001:db8::1]:8443"}
	for input, expected := range cases {
		actual, err := NormalizeServerURL(input, false)
		if err != nil || actual != expected {
			t.Fatalf("%q => %q, %v; want %q", input, actual, err, expected)
		}
	}
	for _, input := range []string{"https://user:pass@host", "https://host/path", "https://%", "file://host", "http://host"} {
		if _, err := NormalizeServerURL(input, false); err == nil {
			t.Fatalf("expected rejection for %q", input)
		}
	}
}

func TestInspectCertificateDoesNotSendHTTPAndPinnedTransportRequiresExactSPKI(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	info, err := InspectServerCertificate(context.Background(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if info.Verified || info.SPKISHA256 == "" || info.Subject == "" || info.NotAfter.IsZero() {
		t.Fatalf("unexpected inspection result: %#v", info)
	}
	if requests.Load() != 0 {
		t.Fatal("certificate inspection sent an HTTP request")
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig, err = PinnedTLSConfig("127.0.0.1", info.SPKISHA256)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: transport}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if requests.Load() != 1 {
		t.Fatalf("pinned request count=%d, want 1", requests.Load())
	}

	wrongPin := strings.Repeat("0", 64)
	wrongTransport := http.DefaultTransport.(*http.Transport).Clone()
	wrongTransport.TLSClientConfig, err = PinnedTLSConfig("127.0.0.1", wrongPin)
	if err != nil {
		t.Fatal(err)
	}
	wrongClient := &http.Client{Transport: wrongTransport}
	if _, err := wrongClient.Get(server.URL); err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("wrong pin was not rejected: %v", err)
	}
	if requests.Load() != 1 {
		t.Fatalf("wrong pin reached HTTP handler: requests=%d", requests.Load())
	}
}

func TestNormalizeSPKIHashCanonicalizesBase64AndHex(t *testing.T) {
	hexValue := strings.Repeat("ab", 32)
	canonical, err := NormalizeSPKIHash(hexValue)
	if err != nil || !strings.HasPrefix(canonical, "sha256/") {
		t.Fatalf("hex normalization: %q %v", canonical, err)
	}
	if _, err := NormalizeSPKIHash("not-a-fingerprint"); err == nil {
		t.Fatal("invalid fingerprint was accepted")
	}
}
