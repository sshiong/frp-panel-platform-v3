package security

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// CertificateInfo is safe to return to the local Client Panel UI. It contains
// certificate metadata and a public-key fingerprint, never a private key or a
// Server credential.
type CertificateInfo struct {
	ServerPanelURL    string    `json:"server_panel_url"`
	Transport         string    `json:"transport"`
	Verified          bool      `json:"verified"`
	VerificationError string    `json:"verification_error,omitempty"`
	Subject           string    `json:"subject,omitempty"`
	Issuer            string    `json:"issuer,omitempty"`
	NotBefore         time.Time `json:"not_before,omitempty"`
	NotAfter          time.Time `json:"not_after,omitempty"`
	SPKISHA256        string    `json:"spki_sha256,omitempty"`
	DNSNames          []string  `json:"dns_names,omitempty"`
	IPAddresses       []string  `json:"ip_addresses,omitempty"`
}

// NormalizeSPKIHash accepts the displayed sha256/base64 fingerprint and a
// hex form for automation/tests, then returns one canonical representation.
func NormalizeSPKIHash(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	value := raw
	value = strings.TrimPrefix(value, "sha256/")
	decoded, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(value, "="))
	if err != nil || len(decoded) != sha256.Size {
		decoded, err = hex.DecodeString(value)
	}
	if err != nil || len(decoded) != sha256.Size {
		return "", fmt.Errorf("SPKI SHA-256 fingerprint must be 32 bytes")
	}
	return "sha256/" + base64.RawStdEncoding.EncodeToString(decoded), nil
}

// SPKISHA256 returns the standard sha256/<base64-without-padding> form.
func SPKISHA256(certificate *x509.Certificate) string {
	digest := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	return "sha256/" + base64.RawStdEncoding.EncodeToString(digest[:])
}

// InspectServerCertificate performs a TLS handshake solely to inspect the
// peer certificate. It intentionally uses an inspection-only connection and
// never sends an HTTP request or a password. Normal system trust is reported
// separately from the handshake so an operator can review and explicitly pin
// an otherwise untrusted IP/custom certificate.
func InspectServerCertificate(ctx context.Context, serverPanelURL string) (CertificateInfo, error) {
	parsed, err := url.Parse(serverPanelURL)
	if err != nil || parsed.Hostname() == "" {
		return CertificateInfo{}, fmt.Errorf("invalid server panel URL")
	}
	info := CertificateInfo{ServerPanelURL: serverPanelURL, Transport: parsed.Scheme}
	if parsed.Scheme != "https" {
		if parsed.Scheme == "http" {
			info.VerificationError = "TLS is not enabled for this development connection"
			return info, nil
		}
		return CertificateInfo{}, fmt.Errorf("certificate inspection requires https")
	}
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	address := net.JoinHostPort(parsed.Hostname(), port)
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	// This is deliberately limited to the metadata inspection path. The
	// application HTTP client below uses ordinary certificate verification unless
	// the user explicitly confirms the displayed fingerprint.
	connection, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{ // #nosec G402 -- inspection does not send HTTP credentials
		MinVersion:         tls.VersionTLS12,
		ServerName:         parsed.Hostname(),
		InsecureSkipVerify: true,
	})
	if err != nil {
		return info, fmt.Errorf("TLS certificate inspection failed: %w", err)
	}
	defer connection.Close()
	state := connection.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return info, fmt.Errorf("server did not present a certificate")
	}
	leaf := state.PeerCertificates[0]
	info.Subject = leaf.Subject.String()
	info.Issuer = leaf.Issuer.String()
	info.NotBefore = leaf.NotBefore
	info.NotAfter = leaf.NotAfter
	info.SPKISHA256 = SPKISHA256(leaf)
	info.DNSNames = append([]string(nil), leaf.DNSNames...)
	for _, address := range leaf.IPAddresses {
		info.IPAddresses = append(info.IPAddresses, address.String())
	}
	if verifyErr := verifyCertificate(leaf, state.PeerCertificates[1:], parsed.Hostname()); verifyErr != nil {
		info.VerificationError = verifyErr.Error()
	} else {
		info.Verified = true
	}
	return info, nil
}

func verifyCertificate(leaf *x509.Certificate, chain []*x509.Certificate, hostname string) error {
	now := time.Now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return fmt.Errorf("certificate is outside its validity period")
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		return fmt.Errorf("system trust store is unavailable")
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range chain {
		intermediates.AddCert(certificate)
	}
	options := x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	// x509.Verify uses DNSName for both DNS names and IP literals; the
	// verifier applies the appropriate SAN matching rule based on the value.
	options.DNSName = hostname
	_, err = leaf.Verify(options)
	return err
}

// PinnedTLSConfig creates a transport configuration for a fingerprint that
// the operator has explicitly reviewed in the Client UI. Certificate validity
// dates and the exact public key are still checked on every connection.
func PinnedTLSConfig(serverName, rawPin string) (*tls.Config, error) {
	pin, err := NormalizeSPKIHash(rawPin)
	if err != nil {
		return nil, err
	}
	if pin == "" {
		return nil, fmt.Errorf("certificate pin is required")
	}
	return &tls.Config{ // #nosec G402 -- explicit SPKI pin is the trust decision
		MinVersion:         tls.VersionTLS12,
		ServerName:         serverName,
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return fmt.Errorf("server did not present a certificate")
			}
			leaf := state.PeerCertificates[0]
			if time.Now().Before(leaf.NotBefore) || time.Now().After(leaf.NotAfter) {
				return fmt.Errorf("server certificate is outside its validity period")
			}
			if SPKISHA256(leaf) != pin {
				return fmt.Errorf("server certificate fingerprint changed")
			}
			return nil
		},
	}, nil
}
