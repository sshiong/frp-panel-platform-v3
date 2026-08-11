package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"

	"github.com/go-chi/chi/v5"
	"github.com/ricardo/frp-panel-platform/client/internal/httpapi"
)

type route struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

func main() {
	routes, err := collectRoutes()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(routes); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func collectRoutes() ([]route, error) {
	var routes []route
	err := chi.Walk(httpapi.RouteManifestRoutes(), func(method, path string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if len(path) >= len("/api/v1") && path[:len("/api/v1")] == "/api/v1" {
			routes = append(routes, route{Method: method, Path: path})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Path == routes[j].Path {
			return routes[i].Method < routes[j].Method
		}
		return routes[i].Path < routes[j].Path
	})
	return routes, nil
}
