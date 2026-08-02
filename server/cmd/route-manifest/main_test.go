package main

import "testing"

func TestCollectRoutes(t *testing.T) {
	routes, err := collectRoutes()
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) < 20 {
		t.Fatalf("expected API route manifest, got %d routes", len(routes))
	}
	for i := range routes {
		if routes[i].Path == "" || routes[i].Method == "" {
			t.Fatalf("invalid route at %d: %#v", i, routes[i])
		}
		if i > 0 && routes[i-1].Path > routes[i].Path {
			t.Fatalf("routes are not sorted: %#v then %#v", routes[i-1], routes[i])
		}
	}
}
