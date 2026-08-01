package security

import (
	"net/url"
	"testing"
)

func FuzzNormalizeServerURL(f *testing.F) {
	for _, seed := range []string{"panel.example.com", "https://127.0.0.1:8443", "https://[2001:db8::1]", "file:///tmp/panel", "https://user:pass@example.com"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		normalized, err := NormalizeServerURL(value, true)
		if err != nil {
			return
		}
		parsed, parseErr := url.Parse(normalized)
		if parseErr != nil || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
			t.Fatalf("successful normalization returned unsafe URL: %q", normalized)
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			t.Fatalf("successful normalization returned unsupported scheme: %q", normalized)
		}
	})
}
