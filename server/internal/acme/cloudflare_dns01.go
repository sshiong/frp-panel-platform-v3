package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ricardo/frp-panel-platform/server/internal/crypto"
	"github.com/ricardo/frp-panel-platform/server/internal/providers/cloudflare"
	"golang.org/x/crypto/acme"
)

type CloudflareDNS01Config struct {
	DirectoryURL   string
	Email          string
	AccountKeyPath string
	CloudflareURL  string
	HTTPClient     *http.Client
	Propagation    time.Duration
}

type CloudflareDNS01Provider struct {
	config CloudflareDNS01Config
	key    []byte
}

type accountState struct {
	AccountURI string `json:"account_uri"`
	KeyDER     []byte `json:"key_der"`
}

func NewCloudflareDNS01(config CloudflareDNS01Config, wrappingKey []byte) (*CloudflareDNS01Provider, error) {
	if len(wrappingKey) != 32 {
		return nil, errors.New("ACME account wrapping key must be 32 bytes")
	}
	if strings.TrimSpace(config.DirectoryURL) == "" || strings.TrimSpace(config.Email) == "" || strings.TrimSpace(config.AccountKeyPath) == "" {
		return nil, errors.New("ACME directory URL and email are required")
	}
	if config.HTTPClient == nil {
		config.HTTPClient = &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	if config.Propagation <= 0 {
		config.Propagation = 2 * time.Minute
	}
	return &CloudflareDNS01Provider{config: config, key: append([]byte(nil), wrappingKey...)}, nil
}

func (p *CloudflareDNS01Provider) IssueDNS01(ctx context.Context, domain string) (Certificate, error) {
	account, err := p.loadOrRegisterAccount(ctx)
	if err != nil {
		return Certificate{}, err
	}
	certificateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Certificate{}, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain}}, certificateKey)
	if err != nil {
		return Certificate{}, err
	}
	client := &acme.Client{Key: account.key, KID: acme.KeyID(account.uri), DirectoryURL: p.config.DirectoryURL, HTTPClient: p.config.HTTPClient, UserAgent: "frp-panel-platform/acme-dns01"}
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(domain))
	if err != nil {
		return Certificate{}, err
	}
	var challengeRecords []dnsChallengeRecord
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		for _, record := range challengeRecords {
			_ = record.provider.DeleteDNS(cleanupCtx, record.zone, record.id)
		}
	}()
	for _, authorizationURL := range order.AuthzURLs {
		authorization, err := client.GetAuthorization(ctx, authorizationURL)
		if err != nil {
			return Certificate{}, err
		}
		if authorization.Status == acme.StatusValid {
			continue
		}
		challenge, err := dnsChallenge(authorization.Challenges)
		if err != nil {
			return Certificate{}, err
		}
		value, err := client.DNS01ChallengeRecord(challenge.Token)
		if err != nil {
			return Certificate{}, err
		}
		provider, zone, err := p.providerAndZone(ctx, authorization.Identifier.Value)
		if err != nil {
			return Certificate{}, err
		}
		record, err := provider.CreateDNS(ctx, zone, cloudflare.Record{Type: "TXT", Name: "_acme-challenge." + authorization.Identifier.Value, Content: value, TTL: 120})
		if err != nil {
			return Certificate{}, err
		}
		if record.ID == "" {
			return Certificate{}, errors.New("cloudflare returned an empty ACME TXT record id")
		}
		challengeRecords = append(challengeRecords, dnsChallengeRecord{provider: provider, zone: zone, id: record.ID})
		if err := waitTXT(ctx, "_acme-challenge."+authorization.Identifier.Value, value, p.config.Propagation); err != nil {
			return Certificate{}, err
		}
		if _, err := client.Accept(ctx, challenge); err != nil {
			return Certificate{}, err
		}
		if _, err := client.WaitAuthorization(ctx, authorization.URI); err != nil {
			return Certificate{}, err
		}
	}
	der, _, err := client.CreateOrderCert(ctx, order.URI, csrDER, true)
	if err != nil {
		return Certificate{}, err
	}
	if len(der) == 0 {
		return Certificate{}, errors.New("ACME returned an empty certificate chain")
	}
	certificate, err := x509.ParseCertificate(der[0])
	if err != nil {
		return Certificate{}, err
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(certificateKey)
	if err != nil {
		return Certificate{}, err
	}
	var certPEM, chainPEM []byte
	for index, item := range der {
		block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: item})
		if index == 0 {
			certPEM = append(certPEM, block...)
		} else {
			chainPEM = append(chainPEM, block...)
		}
	}
	return Certificate{CertPEM: certPEM, ChainPEM: chainPEM, PrivateKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER}), NotBefore: certificate.NotBefore, NotAfter: certificate.NotAfter}, nil
}

type dnsChallengeRecord struct {
	provider *cloudflare.HTTPProvider
	zone     cloudflare.Zone
	id       string
}

type accountMaterial struct {
	key *ecdsa.PrivateKey
	uri string
}

func (p *CloudflareDNS01Provider) loadOrRegisterAccount(ctx context.Context) (accountMaterial, error) {
	if encoded, err := os.ReadFile(p.config.AccountKeyPath); err == nil {
		if len(encoded) < 12 {
			return accountMaterial{}, errors.New("invalid encrypted ACME account")
		}
		plaintext, err := crypto.DecryptWithKey(p.key, encoded[12:], encoded[:12], "acme-account:v1")
		if err != nil {
			return accountMaterial{}, err
		}
		var stored accountState
		if err := json.Unmarshal(plaintext, &stored); err != nil {
			return accountMaterial{}, err
		}
		private, err := x509.ParsePKCS8PrivateKey(stored.KeyDER)
		if err != nil {
			return accountMaterial{}, err
		}
		key, ok := private.(*ecdsa.PrivateKey)
		if !ok || stored.AccountURI == "" {
			return accountMaterial{}, errors.New("invalid stored ACME account")
		}
		return accountMaterial{key: key, uri: stored.AccountURI}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return accountMaterial{}, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return accountMaterial{}, err
	}
	client := &acme.Client{Key: key, DirectoryURL: p.config.DirectoryURL, HTTPClient: p.config.HTTPClient, UserAgent: "frp-panel-platform/acme-dns01"}
	account, err := client.Register(ctx, &acme.Account{Contact: []string{"mailto:" + p.config.Email}}, func(string) bool { return true })
	if err != nil {
		return accountMaterial{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return accountMaterial{}, err
	}
	encoded, err := json.Marshal(accountState{AccountURI: account.URI, KeyDER: keyDER})
	if err != nil {
		return accountMaterial{}, err
	}
	ciphertext, nonce, err := crypto.EncryptWithKey(p.key, encoded, "acme-account:v1")
	if err != nil {
		return accountMaterial{}, err
	}
	if err := os.MkdirAll(filepath.Dir(p.config.AccountKeyPath), 0o700); err != nil {
		return accountMaterial{}, err
	}
	if err := os.WriteFile(p.config.AccountKeyPath, append(nonce, ciphertext...), 0o600); err != nil {
		return accountMaterial{}, err
	}
	return accountMaterial{key: key, uri: account.URI}, nil
}

func (p *CloudflareDNS01Provider) providerAndZone(ctx context.Context, domain string) (*cloudflare.HTTPProvider, cloudflare.Zone, error) {
	token, ok := CloudflareToken(ctx)
	if !ok {
		return nil, cloudflare.Zone{}, errors.New("ACME Cloudflare token is unavailable")
	}
	provider := cloudflare.NewAt(token, p.config.CloudflareURL)
	provider.Client = p.config.HTTPClient
	for page := 1; page <= 100; page++ {
		zones, more, err := provider.ListZones(ctx, page)
		if err != nil {
			return nil, cloudflare.Zone{}, err
		}
		if zone, ok := cloudflare.MatchZone(domain, zones); ok {
			return provider, zone, nil
		}
		if !more {
			break
		}
	}
	return nil, cloudflare.Zone{}, fmt.Errorf("no Cloudflare Zone matches %s", domain)
}

func dnsChallenge(challenges []*acme.Challenge) (*acme.Challenge, error) {
	for _, challenge := range challenges {
		if challenge != nil && challenge.Type == "dns-01" {
			return challenge, nil
		}
	}
	return nil, errors.New("ACME authorization has no dns-01 challenge")
}

func waitTXT(ctx context.Context, name, expected string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	resolver := net.DefaultResolver
	for {
		values, err := resolver.LookupTXT(ctx, name)
		for _, value := range values {
			if strings.TrimSpace(value) == expected {
				return nil
			}
		}
		if time.Now().After(deadline) {
			if err != nil {
				return fmt.Errorf("DNS propagation for %s failed: %w", name, err)
			}
			return fmt.Errorf("DNS propagation for %s timed out", name)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}
