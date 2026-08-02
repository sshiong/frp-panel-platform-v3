package cloudflare

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestHTTPProviderCapabilitiesAndCRUDBranches(t *testing.T) {
	provider := NewAt("coverage-token", "https://api.example.test/client/v4")
	provider.Client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("Authorization") != "Bearer coverage-token" {
			t.Fatalf("missing token header: %q", request.Header.Get("Authorization"))
		}
		payload := map[string]interface{}{"success": true, "result": []interface{}{}}
		switch {
		case request.URL.Path == "/client/v4/user/tokens/verify":
			payload["result"] = map[string]interface{}{}
		case request.URL.Path == "/client/v4/zones":
			payload["result"] = []map[string]string{{"id": "zone-1", "name": "example.com"}}
			payload["result_info"] = map[string]int{"page": 1, "total_pages": 1}
		case request.URL.Path == "/client/v4/zones/zone-1/dns_records" && request.Method == http.MethodGet:
			payload["result"] = []Record{{ID: "record-1", Type: "A", Name: "app.example.com", Content: "192.0.2.10", TTL: 120}}
		case request.URL.Path == "/client/v4/zones/zone-1/dns_records" && request.Method == http.MethodPost:
			payload["result"] = Record{ID: "record-2", Type: "TXT", Name: "_acme-challenge.app.example.com", Content: "value", TTL: 120}
		case request.URL.Path == "/client/v4/zones/zone-1/dns_records/record-1" && request.Method == http.MethodPut:
			payload["result"] = Record{ID: "record-1", Type: "A", Name: "app.example.com", Content: "192.0.2.11", TTL: 120}
		case request.URL.Path == "/client/v4/zones/zone-1/dns_records/record-1" && request.Method == http.MethodDelete:
			payload["result"] = map[string]interface{}{}
		case request.URL.Path == "/error":
			return &http.Response{StatusCode: http.StatusForbidden, Status: "403 Forbidden", Body: io.NopCloser(strings.NewReader(`{"success":false,"errors":[{"message":"permission denied"}]}`)), Header: make(http.Header), Request: request}, nil
		default:
			return &http.Response{StatusCode: http.StatusNotFound, Status: "404 Not Found", Body: io.NopCloser(strings.NewReader(`{"success":false,"errors":[{"message":"unexpected path"}]}`)), Header: make(http.Header), Request: request}, nil
		}
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(string(encoded))), Header: make(http.Header), Request: request}, nil
	})}
	capabilities, err := provider.VerifyToken(context.Background())
	if err != nil || !capabilities.TokenValid || !capabilities.ZoneRead || !capabilities.DNSRead || len(capabilities.Missing) != 0 {
		t.Fatalf("capabilities=%#v err=%v", capabilities, err)
	}
	zones, more, err := provider.ListZones(context.Background(), 1)
	if err != nil || more || len(zones) != 1 || zones[0].ID != "zone-1" {
		t.Fatalf("zones=%#v more=%v err=%v", zones, more, err)
	}
	records, err := provider.ListDNS(context.Background(), zones[0], "app.example.com", "A")
	if err != nil || len(records) != 1 || records[0].Content != "192.0.2.10" {
		t.Fatalf("records=%#v err=%v", records, err)
	}
	created, err := provider.CreateDNS(context.Background(), zones[0], Record{Type: "TXT", Name: "_acme-challenge.app.example.com", Content: "value", TTL: 120})
	if err != nil || created.ID != "record-2" {
		t.Fatalf("created record=%#v err=%v", created, err)
	}
	updated, err := provider.UpsertDNS(context.Background(), zones[0], Record{Type: "A", Name: "app.example.com", Content: "192.0.2.11", TTL: 120})
	if err != nil || updated.Content != "192.0.2.11" {
		t.Fatalf("updated record=%#v err=%v", updated, err)
	}
	if err := provider.DeleteDNS(context.Background(), zones[0], "record-1"); err != nil {
		t.Fatal(err)
	}

	provider.BaseURL = "https://api.example.test/client/v4"
	provider.Client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusForbidden, Status: "403 Forbidden", Body: io.NopCloser(strings.NewReader(`{"success":false,"errors":[{"message":"permission denied"}]}`)), Header: make(http.Header), Request: request}, nil
	})}
	if err := provider.DeleteDNS(context.Background(), Zone{ID: "zone-1"}, "record-1"); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("Cloudflare API error was not preserved: %v", err)
	}
	if err := (&APIError{Status: http.StatusBadGateway, Message: "upstream"}).Error(); err != "cloudflare returned HTTP 502: upstream" {
		t.Fatalf("API error formatting changed: %s", err)
	}
	if (*APIError)(nil).Error() != "cloudflare API error" {
		t.Fatal("nil API error formatting changed")
	}
}
