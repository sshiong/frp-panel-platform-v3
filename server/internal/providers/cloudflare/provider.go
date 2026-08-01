package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type Capabilities struct {
	TokenValid bool     `json:"token_valid"`
	ZoneRead   bool     `json:"zone_read"`
	DNSRead    bool     `json:"dns_read"`
	DNSWrite   bool     `json:"dns_write"`
	Missing    []string `json:"missing"`
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
	UpsertDNS(context.Context, Zone, Record) (Record, error)
	DeleteDNS(context.Context, Zone, string) error
}

type HTTPProvider struct {
	BaseURL string
	Token   string
	Client  *http.Client
}

func New(token string) *HTTPProvider {
	return &HTTPProvider{BaseURL: "https://api.cloudflare.com/client/v4", Token: token, Client: &http.Client{Timeout: 15 * time.Second}}
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
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("cloudflare returned HTTP %d", resp.StatusCode)
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
		return Capabilities{}, err
	}
	return Capabilities{TokenValid: response.Success, ZoneRead: response.Success, DNSRead: response.Success, DNSWrite: response.Success}, nil
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
func (p *HTTPProvider) DeleteDNS(ctx context.Context, zone Zone, recordID string) error {
	return p.request(ctx, http.MethodDelete, "/zones/"+url.PathEscape(zone.ID)+"/dns_records/"+url.PathEscape(recordID), nil, nil)
}
