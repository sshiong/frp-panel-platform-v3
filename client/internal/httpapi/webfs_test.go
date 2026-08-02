package httpapi

import (
	"io/fs"
	"strings"
	"testing"
)

func TestEmbeddedClientFallbackIsAvailable(t *testing.T) {
	web, err := fs.Sub(embeddedWeb, "static/fallback")
	if err != nil {
		t.Fatalf("embedded Client fallback: %v", err)
	}
	content, err := fs.ReadFile(web, "index.html")
	if err != nil || !strings.Contains(string(content), "FRP Panel Client") {
		t.Fatalf("embedded Client fallback index missing: %v", err)
	}
}
