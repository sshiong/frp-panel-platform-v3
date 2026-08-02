package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	internalcrypto "github.com/ricardo/frp-panel-platform/server/internal/crypto"
	"github.com/ricardo/frp-panel-platform/server/internal/id"
)

func TestRouterServiceCertificateMaterialAndFailureEdges(t *testing.T) {
	fixture := newServiceCoverageFixture(t)
	ctx := context.Background()
	app := fixture.app

	if err := app.EnqueueRouterSnapshot(ctx); err != nil {
		t.Fatal(err)
	}
	withoutJobs := *app
	withoutJobs.Jobs = nil
	if err := withoutJobs.EnqueueRouterSnapshot(ctx); err == nil {
		t.Fatal("router enqueue succeeded without a job store")
	}
	if status, err := app.RouterStatus(ctx); err != nil || status.LastGoodVersion != nil || status.Adapter != "file-last-good" {
		t.Fatalf("initial router status: %#v %v", status, err)
	}

	mapping, err := app.CreateMapping(ctx, fixture.client, MappingRequest{Name: "certificate-router", ProxyType: "http", LocalIP: "127.0.0.1", LocalPort: 8120}, "router-cert-map-000001")
	if err != nil {
		t.Fatal(err)
	}
	domain, err := app.CreateDomain(ctx, fixture.client, DomainRequest{MappingID: mapping.ID, Hostname: "cert.example.com", HTTPSMode: "auto_certificate"}, "router-cert-domain-000001")
	if err != nil {
		t.Fatal(err)
	}
	certPEM, privatePEM := testCertificate(t, domain.Normalized)
	certPath := filepath.Join(app.Config.DataDir, "certificates", domain.ID, "cert.pem")
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	ciphertext, nonce, err := internalcrypto.EncryptWithKey(app.Crypto.CertificateKey, privatePEM, "domain:"+domain.ID+":certificate_private_key:v1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.ExecContext(ctx, `INSERT INTO certificates(id,domain_binding_id,provider,status,cert_path,private_key_ciphertext,private_key_nonce,wrapping_key_version,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`, id.New(), domain.ID, "acme", "valid", certPath, ciphertext, nonce, 1, nowString()); err != nil {
		t.Fatal(err)
	}
	certificates, err := app.RouterCertificates(ctx)
	if err != nil || len(certificates) != 1 {
		t.Fatalf("valid router certificate load: %d %v", len(certificates), err)
	}
	if _, ok := certificates[domain.Normalized]; !ok {
		t.Fatalf("certificate hostname was not normalized into the runtime set: %#v", certificates)
	}

	if _, err := app.DB.ExecContext(ctx, `UPDATE certificates SET cert_path=? WHERE domain_binding_id=?`, filepath.Join(os.TempDir(), "outside-cert.pem"), domain.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.RouterCertificates(ctx); err == nil {
		t.Fatal("certificate path outside the data directory was accepted")
	}
	if _, err := app.DB.ExecContext(ctx, `UPDATE certificates SET cert_path='' WHERE domain_binding_id=?`, domain.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.RouterCertificates(ctx); err == nil {
		t.Fatal("incomplete certificate material was accepted")
	}
	if _, err := app.DB.ExecContext(ctx, `UPDATE certificates SET cert_path=?,private_key_ciphertext=?,private_key_nonce=? WHERE domain_binding_id=?`, certPath, []byte("tampered"), nonce, domain.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.RouterCertificates(ctx); err == nil {
		t.Fatal("tampered certificate key was accepted")
	}

	// Restore a valid row and exercise the snapshot adapter with a real route.
	if _, err := app.DB.ExecContext(ctx, `UPDATE certificates SET cert_path=?,private_key_ciphertext=?,private_key_nonce=? WHERE domain_binding_id=?`, certPath, ciphertext, nonce, domain.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.ExecContext(ctx, `UPDATE mappings SET lifecycle_status='running' WHERE id=?`, mapping.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.ExecContext(ctx, `UPDATE domain_bindings SET status='pending_certificate' WHERE id=?`, domain.ID); err != nil {
		t.Fatal(err)
	}
	if snapshot, err := app.BuildRouterSnapshot(ctx); err != nil || snapshot.Version == 0 {
		t.Fatalf("router snapshot with certificate route: %#v %v", snapshot, err)
	}
	if status, err := app.RouterStatus(ctx); err != nil || status.LastGoodVersion == nil || *status.LastGoodVersion == 0 {
		t.Fatalf("router status after snapshot: %#v %v", status, err)
	}

	originalRouterKey := app.Crypto.RouterKey
	app.Crypto.RouterKey = nil
	if _, err := app.BuildRouterSnapshot(ctx); err == nil {
		t.Fatal("router snapshot was built without a router key")
	}
	app.Crypto.RouterKey = originalRouterKey
	if err := app.finalizeDomainRouterStates(ctx, []routeSource{{domainID: domain.ID, domainStatus: "pending_dns"}}, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(app.Config.RouterSnapshotDir, "last-good.json")); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}

type testFatalHelper interface {
	Helper()
	Fatal(...interface{})
}

func testCertificate(t testFatalHelper, hostname string) ([]byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: hostname}, DNSNames: []string{hostname}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return certPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
}
