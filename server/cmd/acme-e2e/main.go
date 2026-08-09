package main

// This command is intentionally operator-only. It exercises a real ACME
// Staging DNS-01 order through the Cloudflare adapter and refuses production
// CA URLs or writes without an explicit confirmation string.

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/ricardo/frp-panel-platform/server/internal/acme"
)

const confirmation = "acme-staging"

const letsEncryptStagingHost = "acme-staging-v02.api.letsencrypt.org"

var domainPattern = regexp.MustCompile(`^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$`)

type result struct {
	SchemaVersion string                 `json:"schema_version"`
	Status        string                 `json:"status"`
	GeneratedAt   string                 `json:"generated_at"`
	Environment   map[string]interface{} `json:"environment"`
	Certificate   map[string]interface{} `json:"certificate,omitempty"`
	Error         string                 `json:"error,omitempty"`
}

func main() {
	status, output := run()
	encoded, _ := json.MarshalIndent(output, "", "  ")
	fmt.Println(string(encoded))
	os.Exit(status)
}

func run() (int, result) {
	token, err := required("CLOUDFLARE_E2E_API_TOKEN")
	if err != nil {
		return failure(err)
	}
	domain, err := required("FRP_ACME_E2E_DOMAIN")
	if err != nil {
		return failure(err)
	}
	if len(domain) > 253 || !domainPattern.MatchString(domain) {
		return failure(errors.New("FRP_ACME_E2E_DOMAIN must be a fully-qualified DNS name"))
	}
	if os.Getenv("FRP_ACME_E2E_CONFIRM") != confirmation {
		return failure(fmt.Errorf("set FRP_ACME_E2E_CONFIRM=%s to authorize an ACME Staging order", confirmation))
	}
	directory := os.Getenv("FRP_ACME_E2E_DIRECTORY_URL")
	if directory == "" {
		return failure(errors.New("FRP_ACME_E2E_DIRECTORY_URL is required and must be an ACME Staging URL"))
	}
	if err := validateStagingDirectory(directory); err != nil {
		return failure(err)
	}
	if len(token) == 0 {
		return failure(errors.New("CLOUDFLARE_E2E_API_TOKEN must not be empty"))
	}

	root, err := os.MkdirTemp("", "frp-acme-e2e-")
	if err != nil {
		return failure(fmt.Errorf("create temporary ACME directory: %w", err))
	}
	defer os.RemoveAll(root)
	wrappingKey := make([]byte, 32)
	if _, err := rand.Read(wrappingKey); err != nil {
		return failure(fmt.Errorf("generate temporary wrapping key: %w", err))
	}
	propagation := 2 * time.Minute
	if value := os.Getenv("FRP_ACME_E2E_PROPAGATION_TIMEOUT"); value != "" {
		propagation, err = time.ParseDuration(value)
		if err != nil || propagation <= 0 {
			return failure(errors.New("FRP_ACME_E2E_PROPAGATION_TIMEOUT must be a positive duration"))
		}
	}
	provider, err := acme.NewCloudflareDNS01(acme.CloudflareDNS01Config{
		DirectoryURL:   directory,
		Email:          os.Getenv("FRP_ACME_E2E_EMAIL"),
		AccountKeyPath: filepath.Join(root, "account.key"),
		CloudflareURL:  os.Getenv("CLOUDFLARE_API_BASE_URL"),
		Propagation:    propagation,
	}, wrappingKey)
	if err != nil {
		return failure(fmt.Errorf("configure ACME DNS-01 provider: %w", err))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	certificate, err := provider.IssueDNS01(acme.WithCloudflareToken(ctx, token), domain)
	if err != nil {
		return failure(fmt.Errorf("ACME Staging DNS-01 failed: %w", err))
	}
	if len(certificate.CertPEM) == 0 || certificate.NotAfter.IsZero() {
		return failure(errors.New("ACME provider returned incomplete certificate metadata"))
	}
	return 0, result{
		SchemaVersion: "v1",
		Status:        "passed",
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339Nano),
		Environment: map[string]interface{}{
			"ca":     "ACME Staging",
			"domain": domain,
		},
		Certificate: map[string]interface{}{
			"not_before":  certificate.NotBefore.UTC().Format(time.RFC3339Nano),
			"not_after":   certificate.NotAfter.UTC().Format(time.RFC3339Nano),
			"chain_bytes": len(certificate.ChainPEM),
		},
	}
}

func validateStagingDirectory(raw string) error {
	directoryURL, err := url.Parse(raw)
	if err != nil || directoryURL.Scheme != "https" || directoryURL.User != nil ||
		directoryURL.Hostname() != letsEncryptStagingHost || directoryURL.Port() != "" ||
		directoryURL.Path != "/directory" || directoryURL.RawQuery != "" || directoryURL.Fragment != "" {
		return errors.New("FRP_ACME_E2E_DIRECTORY_URL must be exactly the official HTTPS ACME Staging directory")
	}
	return nil
}

func required(name string) (string, error) {
	value := os.Getenv(name)
	if value == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	return value, nil
}

func failure(err error) (int, result) {
	return 1, result{
		SchemaVersion: "v1",
		Status:        "failed",
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339Nano),
		Error:         err.Error(),
	}
}
