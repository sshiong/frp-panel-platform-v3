package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/ricardo/frp-panel-platform/server/internal/clock"
)

type Capabilities struct {
	TokenValid      bool     `json:"token_valid"`
	ZoneRead        bool     `json:"zone_read"`
	DNSRead         bool     `json:"dns_read"`
	DNSWrite        bool     `json:"dns_write"`
	DNSWriteChecked bool     `json:"dns_write_checked"`
	Missing         []string `json:"missing"`
}

// APIError preserves the HTTP status so callers can distinguish a denied
// permission from a transient Cloudflare/network failure.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string {
	if e == nil {
		return "cloudflare API error"
	}
	return fmt.Sprintf("cloudflare returned HTTP %d: %s", e.Status, e.Message)
}

type Zone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type Record struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
}
type Provider interface {
	VerifyToken(context.Context) (Capabilities, error)
	ListZones(context.Context, int) ([]Zone, bool, error)
	ListDNS(context.Context, Zone, string, string) ([]Record, error)
	CreateDNS(context.Context, Zone, Record) (Record, error)
	UpsertDNS(context.Context, Zone, Record) (Record, error)
	DeleteDNS(context.Context, Zone, string) error
}

type HTTPProvider struct {
	BaseURL string
	Token   string
	Client  *http.Client
}

func New(token string) *HTTPProvider {
	return &HTTPProvider{
		BaseURL: "https://api.cloudflare.com/client/v4",
		Token:   token,
		Client: &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func NewAt(token, baseURL string) *HTTPProvider {
	provider := New(token)
	if baseURL != "" {
		provider.BaseURL = baseURL
	}
	return provider
}

func (p *HTTPProvider) request(ctx context.Context, method, path string, body interface{}, target interface{}) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.BaseURL+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.Token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := p.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := clock.ValidateResponse(resp, clock.DefaultTolerance); err != nil {
		return err
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var envelope struct {
		Success bool `json:"success"`
		Errors  []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		message := resp.Status
		if json.Unmarshal(data, &envelope) == nil && len(envelope.Errors) > 0 && envelope.Errors[0].Message != "" {
			message = envelope.Errors[0].Message
		}
		return &APIError{Status: resp.StatusCode, Message: message}
	}
	if len(data) > 0 && json.Unmarshal(data, &envelope) == nil && !envelope.Success && len(envelope.Errors) > 0 {
		return fmt.Errorf("cloudflare: %s", envelope.Errors[0].Message)
	}
	if target != nil && len(data) > 0 {
		return json.Unmarshal(data, target)
	}
	return nil
}

func (p *HTTPProvider) VerifyToken(ctx context.Context) (Capabilities, error) {
	var response struct {
		Success bool `json:"success"`
	}
	if err := p.request(ctx, http.MethodGet, "/user/tokens/verify", nil, &response); err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && (apiErr.Status == http.StatusUnauthorized || apiErr.Status == http.StatusForbidden) {
			return Capabilities{Missing: []string{"Token.Verify"}}, nil
		}
		return Capabilities{}, err
	}
	capabilities := Capabilities{TokenValid: response.Success, Missing: make([]string, 0)}
	if !response.Success {
		return capabilities, nil
	}
	zones, _, err := p.ListZones(ctx, 1)
	if err != nil {
		var apiErr *APIError
		if !errors.As(err, &apiErr) || (apiErr.Status != http.StatusUnauthorized && apiErr.Status != http.StatusForbidden) {
			return capabilities, err
		}
		capabilities.Missing = append(capabilities.Missing, "Zone.Read")
		return capabilities, nil
	}
	capabilities.ZoneRead = true
	if len(zones) == 0 {
		// No accessible Zone means DNS.Read cannot be proven, but this is not a
		// token failure. The UI keeps the integration pending until a Zone exists.
		capabilities.Missing = append(capabilities.Missing, "DNS.Read")
		return capabilities, nil
	}
	if _, err := p.ListDNS(ctx, zones[0], "", ""); err != nil {
		var apiErr *APIError
		if !errors.As(err, &apiErr) || (apiErr.Status != http.StatusUnauthorized && apiErr.Status != http.StatusForbidden) {
			return capabilities, err
		}
		capabilities.Missing = append(capabilities.Missing, "DNS.Read")
		return capabilities, nil
	}
	capabilities.DNSRead = true
	// A write probe would mutate a customer Zone. It is intentionally not
	// executed by default; a configured Cloudflare sandbox can provide one.
	return capabilities, nil
}
func (p *HTTPProvider) ListZones(ctx context.Context, page int) ([]Zone, bool, error) {
	var response struct {
		Result     []Zone `json:"result"`
		ResultInfo struct {
			Page       int `json:"page"`
			TotalPages int `json:"total_pages"`
		} `json:"result_info"`
	}
	path := "/zones?page=" + url.QueryEscape(strconv.Itoa(page)) + "&per_page=50"
	if err := p.request(ctx, http.MethodGet, path, nil, &response); err != nil {
		return nil, false, err
	}
	return response.Result, page < response.ResultInfo.TotalPages, nil
}
func (p *HTTPProvider) ListDNS(ctx context.Context, zone Zone, name, recordType string) ([]Record, error) {
	var response struct {
		Result []Record `json:"result"`
	}
	path := "/zones/" + url.PathEscape(zone.ID) + "/dns_records?per_page=100"
	if name != "" {
		path += "&name=" + url.QueryEscape(name)
	}
	if recordType != "" {
		path += "&type=" + url.QueryEscape(recordType)
	}
	if err := p.request(ctx, http.MethodGet, path, nil, &response); err != nil {
		return nil, err
	}
	return response.Result, nil
}
func (p *HTTPProvider) UpsertDNS(ctx context.Context, zone Zone, record Record) (Record, error) {
	var existing struct {
		Result []Record `json:"result"`
	}
	query := "/zones/" + url.PathEscape(zone.ID) + "/dns_records?type=" + url.QueryEscape(record.Type) + "&name=" + url.QueryEscape(record.Name) + "&per_page=1"
	if err := p.request(ctx, http.MethodGet, query, nil, &existing); err != nil {
		return Record{}, err
	}
	payload := map[string]interface{}{
		"type":    record.Type,
		"name":    record.Name,
		"content": record.Content,
		"ttl":     record.TTL,
		"proxied": record.Proxied,
	}
	if len(existing.Result) == 0 {
		var created struct {
			Result Record `json:"result"`
		}
		if err := p.request(ctx, http.MethodPost, "/zones/"+url.PathEscape(zone.ID)+"/dns_records", payload, &created); err != nil {
			return Record{}, err
		}
		return created.Result, nil
	}
	var updated struct {
		Result Record `json:"result"`
	}
	path := "/zones/" + url.PathEscape(zone.ID) + "/dns_records/" + url.PathEscape(existing.Result[0].ID)
	if err := p.request(ctx, http.MethodPut, path, payload, &updated); err != nil {
		return Record{}, err
	}
	return updated.Result, nil
}

func (p *HTTPProvider) CreateDNS(ctx context.Context, zone Zone, record Record) (Record, error) {
	payload := map[string]interface{}{
		"type":    record.Type,
		"name":    record.Name,
		"content": record.Content,
		"ttl":     record.TTL,
		"proxied": record.Proxied,
	}
	var created struct {
		Result Record `json:"result"`
	}
	if err := p.request(ctx, http.MethodPost, "/zones/"+url.PathEscape(zone.ID)+"/dns_records", payload, &created); err != nil {
		return Record{}, err
	}
	return created.Result, nil
}
func (p *HTTPProvider) DeleteDNS(ctx context.Context, zone Zone, recordID string) error {
	return p.request(ctx, http.MethodDelete, "/zones/"+url.PathEscape(zone.ID)+"/dns_records/"+url.PathEscape(recordID), nil, nil)
}
