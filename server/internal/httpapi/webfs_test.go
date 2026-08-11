package httpapi

import (
	"io/fs"
	"strings"
	"testing"
)

func TestEmbeddedAdminFallbackIsAvailable(t *testing.T) {
	web, err := fs.Sub(embeddedWeb, "static/fallback")
	if err != nil {
		t.Fatalf("embedded Admin fallback: %v", err)
	}
	content, err := fs.ReadFile(web, "index.html")
	if err != nil || !strings.Contains(string(content), "FRP Panel Server") {
		t.Fatalf("embedded Admin fallback index missing: %v", err)
	}
}
