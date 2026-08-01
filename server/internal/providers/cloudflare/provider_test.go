package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func TestHTTPProviderDNSLifecycle(t *testing.T) {
	var record Record
	provider := New("test-token")
	provider.BaseURL = "https://api.example.test/client/v4"
	provider.Client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			return nil, &urlError{"missing bearer token"}
		}
		var payload interface{}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/client/v4/zones/zone-1/dns_records":
			if record.ID == "" {
				payload = map[string]interface{}{"success": true, "result": []Record{}}
			} else {
				payload = map[string]interface{}{"success": true, "result": []Record{record}}
			}
		case r.Method == http.MethodPost && r.URL.Path == "/client/v4/zones/zone-1/dns_records":
			record = Record{ID: "record-1", Type: "A", Name: "app.example.com", Content: "192.0.2.10", TTL: 120}
			payload = map[string]interface{}{"success": true, "result": record}
		case r.Method == http.MethodPut && r.URL.Path == "/client/v4/zones/zone-1/dns_records/record-1":
			record.Content = "192.0.2.11"
			payload = map[string]interface{}{"success": true, "result": record}
		case r.Method == http.MethodDelete && r.URL.Path == "/client/v4/zones/zone-1/dns_records/record-1":
			payload = map[string]interface{}{"success": true, "result": map[string]string{}}
		default:
			return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(bytes.NewReader(nil)), Header: make(http.Header), Request: r}, nil
		}
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(encoded)), Header: make(http.Header), Request: r}, nil
	})}

	created, err := provider.UpsertDNS(context.Background(), Zone{ID: "zone-1"}, Record{Type: "A", Name: "app.example.com", Content: "192.0.2.10", TTL: 120})
	if err != nil || created.ID != "record-1" {
		t.Fatalf("create: %#v %v", created, err)
	}
	updated, err := provider.UpsertDNS(context.Background(), Zone{ID: "zone-1"}, Record{Type: "A", Name: "app.example.com", Content: "192.0.2.11", TTL: 120})
	if err != nil || updated.Content != "192.0.2.11" {
		t.Fatalf("update: %#v %v", updated, err)
	}
	if err := provider.DeleteDNS(context.Background(), Zone{ID: "zone-1"}, "record-1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
}

type urlError struct{ message string }

func (e *urlError) Error() string { return e.message }
