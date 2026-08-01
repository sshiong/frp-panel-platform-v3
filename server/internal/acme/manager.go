package acme

import (
	"context"
	"errors"
	"time"
)

var ErrUnavailable = errors.New("ACME provider is not configured")

// Certificate is deliberately transport-neutral. The production adapter can
// be backed by lego or another mature ACME client without leaking that
// dependency into the Control/Router boundary.
type Certificate struct {
	CertPEM    []byte
	ChainPEM   []byte
	PrivateKey []byte
	NotBefore  time.Time
	NotAfter   time.Time
}

type Provider interface {
	IssueDNS01(context.Context, string) (Certificate, error)
}

type Manager struct {
	Enabled      bool
	DirectoryURL string
	Email        string
	Provider     Provider
}

type contextKey string

const cloudflareTokenKey contextKey = "cloudflare-token"

func WithCloudflareToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, cloudflareTokenKey, token)
}

func CloudflareToken(ctx context.Context) (string, bool) {
	token, ok := ctx.Value(cloudflareTokenKey).(string)
	return token, ok && token != ""
}

func (m Manager) IssueDNS01(ctx context.Context, domain string) (Certificate, error) {
	if !m.Enabled || m.Provider == nil {
		return Certificate{}, ErrUnavailable
	}
	if domain == "" {
		return Certificate{}, errors.New("ACME domain is required")
	}
	return m.Provider.IssueDNS01(ctx, domain)
}
