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
	"strings"
	"time"

	"github.com/ricardo/frp-panel-platform/server/internal/acme"
)

const confirmation = "acme-staging"

const letsEncryptStagingHost = "acme-staging-v02.api.letsencrypt.org"

var domainPattern = regexp.MustCompile(`^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$`)

type result struct {
	SchemaVersion string                 `json:"schema_version"`
	Status        string                 `json:"status"`
	Repository    string                 `json:"repository"`
	Commit        string                 `json:"commit,omitempty"`
	GeneratedAt   string                 `json:"generated_at"`
	Environment   map[string]interface{} `json:"environment"`
	Steps         []runnerStep           `json:"steps"`
	RequestIDs    []string               `json:"request_ids"`
	Certificate   map[string]interface{} `json:"certificate,omitempty"`
	Error         string                 `json:"error,omitempty"`
}

type runnerStep struct {
	ID         string `json:"id"`
	Title      string `json:"title"`
	Status     string `json:"status"`
	ExecutedAt string `json:"executed_at"`
}

func main() {
	status, output := run()
	encoded, _ := json.MarshalIndent(output, "", "  ")
	fmt.Println(string(encoded))
	os.Exit(status)
}

func run() (int, result) {
	commit := os.Getenv("FRP_ACCEPTANCE_EXPECTED_COMMIT")
	if commit == "" {
		commit = os.Getenv("GITHUB_SHA")
	}
	if commit != "" && !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(commit) {
		return failureWithCommit(commit, errors.New("FRP_ACCEPTANCE_EXPECTED_COMMIT must be a 40-character commit SHA"))
	}
	token, err := required("CLOUDFLARE_E2E_API_TOKEN")
	if err != nil {
		return failureWithCommit(commit, err)
	}
	domain, err := required("FRP_ACME_E2E_DOMAIN")
	if err != nil {
		return failureWithCommit(commit, err)
	}
	domain = normalizeHostname(domain)
	if len(domain) > 253 || !domainPattern.MatchString(domain) {
		return failureWithCommit(commit, errors.New("FRP_ACME_E2E_DOMAIN must be a fully-qualified DNS name"))
	}
	expectedZone, err := required("FRP_ACME_E2E_EXPECTED_ZONE_NAME")
	if err != nil {
		return failureWithCommit(commit, err)
	}
	expectedZone = normalizeHostname(expectedZone)
	if len(expectedZone) > 253 || !domainPattern.MatchString(expectedZone) {
		return failureWithCommit(commit, errors.New("FRP_ACME_E2E_EXPECTED_ZONE_NAME must be a fully-qualified DNS name"))
	}
	if !hostnameInZone(domain, expectedZone) {
		return failureWithCommit(commit, fmt.Errorf("FRP_ACME_E2E_DOMAIN %s is outside expected Cloudflare Zone %s", domain, expectedZone))
	}
	if os.Getenv("FRP_ACME_E2E_CONFIRM") != confirmation {
		return failureWithCommit(commit, fmt.Errorf("set FRP_ACME_E2E_CONFIRM=%s to authorize an ACME Staging order", confirmation))
	}
	directory := os.Getenv("FRP_ACME_E2E_DIRECTORY_URL")
	if directory == "" {
		return failureWithCommit(commit, errors.New("FRP_ACME_E2E_DIRECTORY_URL is required and must be an ACME Staging URL"))
	}
	if err := validateStagingDirectory(directory); err != nil {
		return failureWithCommit(commit, err)
	}
	if len(token) == 0 {
		return failureWithCommit(commit, errors.New("CLOUDFLARE_E2E_API_TOKEN must not be empty"))
	}

	root, err := os.MkdirTemp("", "frp-acme-e2e-")
	if err != nil {
		return failureWithCommit(commit, fmt.Errorf("create temporary ACME directory: %w", err))
	}
	defer os.RemoveAll(root)
	wrappingKey := make([]byte, 32)
	if _, err := rand.Read(wrappingKey); err != nil {
		return failureWithCommit(commit, fmt.Errorf("generate temporary wrapping key: %w", err))
	}
	propagation := 2 * time.Minute
	if value := os.Getenv("FRP_ACME_E2E_PROPAGATION_TIMEOUT"); value != "" {
		propagation, err = time.ParseDuration(value)
		if err != nil || propagation <= 0 {
			return failureWithCommit(commit, errors.New("FRP_ACME_E2E_PROPAGATION_TIMEOUT must be a positive duration"))
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
		return failureWithCommit(commit, fmt.Errorf("configure ACME DNS-01 provider: %w", err))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	certificate, err := provider.IssueDNS01(acme.WithCloudflareToken(ctx, token), domain)
	if err != nil {
		return failureWithCommit(commit, fmt.Errorf("ACME Staging DNS-01 failed: %w", err))
	}
	if len(certificate.CertPEM) == 0 || certificate.NotAfter.IsZero() {
		return failureWithCommit(commit, errors.New("ACME provider returned incomplete certificate metadata"))
	}
	executedAt := time.Now().UTC().Format(time.RFC3339Nano)
	return 0, result{
		SchemaVersion: "v1",
		Status:        "passed",
		Repository:    "sshiong/frp-panel-platform-v3",
		Commit:        commit,
		GeneratedAt:   executedAt,
		Environment: map[string]interface{}{
			"ca":     "ACME Staging",
			"domain": domain,
			"zone":   expectedZone,
		},
		Steps: []runnerStep{
			{ID: "input-validation", Title: "Validate the official ACME Staging and disposable Zone inputs", Status: "passed", ExecutedAt: executedAt},
			{ID: "dns01-order", Title: "Issue one ACME Staging DNS-01 certificate", Status: "passed", ExecutedAt: executedAt},
			{ID: "certificate-validation", Title: "Validate returned certificate metadata", Status: "passed", ExecutedAt: executedAt},
		},
		RequestIDs: []string{},
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

func normalizeHostname(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}

func hostnameInZone(hostname, zoneName string) bool {
	hostname = normalizeHostname(hostname)
	zoneName = normalizeHostname(zoneName)
	if hostname == "" || zoneName == "" {
		return false
	}
	return hostname == zoneName || strings.HasSuffix(hostname, "."+zoneName)
}

func failureWithCommit(commit string, err error) (int, result) {
	return 1, result{
		SchemaVersion: "v1",
		Status:        "failed",
		Repository:    "sshiong/frp-panel-platform-v3",
		Commit:        commit,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339Nano),
		Steps:         []runnerStep{},
		RequestIDs:    []string{},
		Error:         redactError(err.Error()),
	}
}

func redactError(message string) string {
	for _, secret := range []string{
		os.Getenv("CLOUDFLARE_E2E_API_TOKEN"),
		os.Getenv("FRP_ACME_E2E_EMAIL"),
	} {
		if secret != "" {
			message = strings.ReplaceAll(message, secret, "[REDACTED]")
		}
	}
	return message
}
