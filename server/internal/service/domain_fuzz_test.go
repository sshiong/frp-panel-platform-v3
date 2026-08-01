package service

import "testing"

func FuzzNormalizeDomain(f *testing.F) {
	for _, seed := range []string{"app.example.com", "APP.Example.com.", "xn--bcher-kva.example", "https://example.com/path", "a..example.com"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		normalized, err := normalizeDomain(value)
		if err == nil {
			if normalized == "" || len(normalized) > 253 {
				t.Fatalf("invalid normalized domain %q", normalized)
			}
			if again, secondErr := normalizeDomain(normalized); secondErr != nil || again != normalized {
				t.Fatalf("normalization is not stable: %q -> %q (%v)", normalized, again, secondErr)
			}
		}
	})
}
