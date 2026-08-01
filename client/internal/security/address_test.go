package security

import "testing"

func TestNormalizeServerURL(t *testing.T) {
	cases := map[string]string{"panel.example.com": "https://panel.example.com", "panel.example.com:8443": "https://panel.example.com:8443", "https://203.0.113.10": "https://203.0.113.10", "https://[2001:db8::1]:8443": "https://[2001:db8::1]:8443"}
	for input, expected := range cases {
		actual, err := NormalizeServerURL(input, false)
		if err != nil || actual != expected {
			t.Fatalf("%q => %q, %v; want %q", input, actual, err, expected)
		}
	}
	for _, input := range []string{"https://user:pass@host", "https://host/path", "file://host", "http://host"} {
		if _, err := NormalizeServerURL(input, false); err == nil {
			t.Fatalf("expected rejection for %q", input)
		}
	}
}
