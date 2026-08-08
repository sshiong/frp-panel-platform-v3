package httpapi

import (
	"bytes"
	"embed"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// embeddedWeb contains the Client Panel built by the release pipeline. The
// generated directory is populated by Make/Docker immediately before the Go
// binary is compiled; the placeholder keeps `go test ./...` valid before a UI
// build has been requested.
//
//go:embed all:static/fallback all:static/generated
var embeddedWeb embed.FS

func (a *API) webFS() fs.FS {
	candidates := []string{"web/client/dist", "../web/client/dist"}
	if a.App != nil {
		candidates = append([]string{a.App.Config.ClientWebDir}, candidates...)
	}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		absolute, err := filepath.Abs(candidate)
		if err != nil {
			continue
		}
		if _, err := os.Stat(filepath.Join(absolute, "index.html")); err == nil {
			return os.DirFS(absolute)
		}
	}
	if web, err := fs.Sub(embeddedWeb, "static/generated"); err == nil {
		if _, statErr := fs.Stat(web, "index.html"); statErr == nil {
			return web
		}
	}
	web, err := fs.Sub(embeddedWeb, "static/fallback")
	if err == nil {
		return web
	}
	// The embed patterns are compile-time checked, so this is defensive only.
	return os.DirFS(".")
}

func serveWebFile(w http.ResponseWriter, r *http.Request, web fs.FS, name string) {
	content, err := fs.ReadFile(web, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(content))
}
