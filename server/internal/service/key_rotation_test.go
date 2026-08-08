package service

import (
	"context"
	"testing"

	"github.com/ricardo/frp-panel-platform/server/internal/id"
)

func TestRotateEncryptionKeysRewrapsDatabaseSecrets(t *testing.T) {
	fixture := newServiceCoverageFixture(t)
	ctx := context.Background()
	app := fixture.app

	var oldFRPCiphertext, oldFRNonce []byte
	var oldFRPVersion int64
	if err := app.DB.QueryRowContext(ctx, `SELECT secret_ciphertext,secret_nonce,key_version FROM frp_credentials WHERE user_id=?`, fixture.user.ID).Scan(&oldFRPCiphertext, &oldFRNonce, &oldFRPVersion); err != nil {
		t.Fatal(err)
	}
	if oldFRPVersion != 1 {
		t.Fatalf("new FRP credential was not written with key version 1: %d", oldFRPVersion)
	}

	cloudflareToken := "rotation-cloudflare-token-abcdefghijklmnopqrstuvwxyz"
	cloudflareCiphertext, cloudflareNonce, err := app.Crypto.Encrypt([]byte(cloudflareToken), "user:"+fixture.user.ID+":cloudflare_token:v1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.ExecContext(ctx, `INSERT INTO cloudflare_credentials(id,user_id,token_version,ciphertext,nonce,key_version,status,capabilities_json,created_at) VALUES(?,?,?,?,?,?,'pending','{}',?)`, id.New(), fixture.user.ID, 1, cloudflareCiphertext, cloudflareNonce, 1, nowString()); err != nil {
		t.Fatal(err)
	}

	mapping, err := app.CreateMapping(ctx, fixture.client, MappingRequest{Name: "rotation-cert-map", ProxyType: "http", LocalIP: "127.0.0.1", LocalPort: 8321}, "rotation-cert-map-000001")
	if err != nil {
		t.Fatal(err)
	}
	domain, err := app.CreateDomain(ctx, fixture.client, DomainRequest{MappingID: mapping.ID, Hostname: "rotation.example.com", HTTPSMode: "auto_certificate"}, "rotation-cert-domain-000001")
	if err != nil {
		t.Fatal(err)
	}
	certificatePlaintext := []byte("rotation-private-key")
	certificateCiphertext, certificateNonce, err := app.Crypto.EncryptCertificate(certificatePlaintext, "domain:"+domain.ID+":certificate_private_key:v1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.ExecContext(ctx, `INSERT INTO certificates(id,domain_binding_id,provider,status,private_key_ciphertext,private_key_nonce,wrapping_key_version,updated_at) VALUES(?,?,?,?,?,?,?,?)`, id.New(), domain.ID, "acme", "valid", certificateCiphertext, certificateNonce, 1, nowString()); err != nil {
		t.Fatal(err)
	}

	result, err := app.RotateEncryptionKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if result.MasterKeyVersion != 2 || result.CertificateKeyVersion != 2 || result.FRPCredentials != 2 || result.CloudflareCredentials != 1 || result.Certificates != 1 {
		t.Fatalf("unexpected rotation result: %#v", result)
	}

	var newFRPCiphertext, newFRNonce []byte
	var newFRPVersion int64
	if err := app.DB.QueryRowContext(ctx, `SELECT secret_ciphertext,secret_nonce,key_version FROM frp_credentials WHERE user_id=?`, fixture.user.ID).Scan(&newFRPCiphertext, &newFRNonce, &newFRPVersion); err != nil {
		t.Fatal(err)
	}
	if newFRPVersion != 2 || string(newFRPCiphertext) == string(oldFRPCiphertext) || string(newFRNonce) == string(oldFRNonce) {
		t.Fatal("FRP credential was not rewrapped with the new key")
	}
	if plaintext, err := app.Crypto.DecryptVersioned(1, oldFRPCiphertext, oldFRNonce, "user:"+fixture.user.ID+":frp_secret:v1"); err != nil || len(plaintext) == 0 {
		t.Fatalf("old FRP ciphertext is not retained: %q %v", plaintext, err)
	}
	if plaintext, err := app.Crypto.DecryptVersioned(2, newFRPCiphertext, newFRNonce, "user:"+fixture.user.ID+":frp_secret:v1"); err != nil || len(plaintext) == 0 {
		t.Fatalf("new FRP ciphertext is not readable: %q %v", plaintext, err)
	}

	var cloudflareVersion int64
	if err := app.DB.QueryRowContext(ctx, `SELECT key_version FROM cloudflare_credentials WHERE user_id=?`, fixture.user.ID).Scan(&cloudflareVersion); err != nil {
		t.Fatal(err)
	}
	if cloudflareVersion != 2 {
		t.Fatalf("Cloudflare credential key version = %d, want 2", cloudflareVersion)
	}
	var certificateVersion int64
	if err := app.DB.QueryRowContext(ctx, `SELECT wrapping_key_version FROM certificates WHERE domain_binding_id=?`, domain.ID).Scan(&certificateVersion); err != nil {
		t.Fatal(err)
	}
	if certificateVersion != 2 {
		t.Fatalf("certificate key version = %d, want 2", certificateVersion)
	}

	login, err := app.Login(ctx, fixture.user.Username, fixture.password, "client_panel", "127.0.0.1", "rotation-test")
	if err != nil {
		t.Fatalf("client login after key rotation failed: %v", err)
	}
	if login.FRPSecret == "" || login.FRPUsername == "" {
		t.Fatal("client login did not recover the rewrapped FRP credential")
	}
}
