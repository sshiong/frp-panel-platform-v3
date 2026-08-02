package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type failingRandomReader struct{}

func (failingRandomReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestEncryptUsesAAD(t *testing.T) {
	manager := &Manager{MasterKey: []byte("01234567890123456789012345678901")}
	ciphertext, nonce, err := manager.Encrypt([]byte("token-value"), "user:u:token:v1")
	if err != nil {
		t.Fatal(err)
	}
	plain, err := manager.Decrypt(ciphertext, nonce, "user:u:token:v1")
	if err != nil || string(plain) != "token-value" {
		t.Fatalf("decrypt mismatch: %q %v", plain, err)
	}
	if _, err := manager.Decrypt(ciphertext, nonce, "user:other:token:v1"); err == nil {
		t.Fatal("AAD mismatch must fail")
	}
}

func TestLoadCreatesAndReusesPurposeSpecificKeys(t *testing.T) {
	dataDir := t.TempDir()
	masterPath := filepath.Join(dataDir, "keys", "master.key")
	signingPath := filepath.Join(dataDir, "keys", "signing.key")
	first, err := Load(dataDir, masterPath, signingPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.MasterKey) != 32 || len(first.RouterKey) != 32 || len(first.CertificateKey) != 32 || len(first.SignKey) != ed25519.PrivateKeySize {
		t.Fatalf("unexpected key sizes: master=%d router=%d certificate=%d signing=%d", len(first.MasterKey), len(first.RouterKey), len(first.CertificateKey), len(first.SignKey))
	}
	if first.KeyID == "" {
		t.Fatal("missing signing key id")
	}
	if _, err := base64.RawURLEncoding.DecodeString(first.KeyID); err != nil {
		t.Fatalf("key id is not URL-safe base64: %v", err)
	}
	second, err := Load(dataDir, masterPath, signingPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(first.MasterKey) != string(second.MasterKey) || string(first.RouterKey) != string(second.RouterKey) || string(first.CertificateKey) != string(second.CertificateKey) || string(first.SignKey) != string(second.SignKey) || first.KeyID != second.KeyID {
		t.Fatal("Load did not reuse the existing key material")
	}
	for _, path := range []string{masterPath, signingPath, filepath.Join(dataDir, "router-snapshot.key"), filepath.Join(dataDir, "certificate-wrapping.key")} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("key %s mode=%o, want 600", path, info.Mode().Perm())
		}
	}
}

func TestLoadRejectsInvalidPersistedKeyLength(t *testing.T) {
	dataDir := t.TempDir()
	masterPath := filepath.Join(dataDir, "master.key")
	if err := os.WriteFile(masterPath, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dataDir, masterPath, filepath.Join(dataDir, "signing.key")); err == nil || !strings.Contains(err.Error(), "master key") {
		t.Fatalf("expected invalid master key error, got %v", err)
	}
	if err := os.WriteFile(masterPath, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "signing.key"), []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dataDir, masterPath, filepath.Join(dataDir, "signing.key")); err == nil || !strings.Contains(err.Error(), "config signing key") {
		t.Fatalf("expected invalid signing key error, got %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "signing.key"), make([]byte, ed25519.PrivateKeySize), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "router-snapshot.key"), []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dataDir, masterPath, filepath.Join(dataDir, "signing.key")); err == nil || !strings.Contains(err.Error(), "router snapshot key") {
		t.Fatalf("expected invalid router key error, got %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "router-snapshot.key"), make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "certificate-wrapping.key"), []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dataDir, masterPath, filepath.Join(dataDir, "signing.key")); err == nil || !strings.Contains(err.Error(), "certificate wrapping key") {
		t.Fatalf("expected invalid certificate key error, got %v", err)
	}
}

func TestPurposeKeyValidationAndSignature(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	ciphertext, nonce, err := EncryptWithKey(key, []byte("certificate"), "certificate:v1")
	if err != nil {
		t.Fatal(err)
	}
	plain, err := DecryptWithKey(key, ciphertext, nonce, "certificate:v1")
	if err != nil || string(plain) != "certificate" {
		t.Fatalf("purpose-key decrypt mismatch: %q %v", plain, err)
	}
	if _, _, err := EncryptWithKey([]byte("bad"), []byte("value"), "aad"); err == nil {
		t.Fatal("invalid AES key was accepted")
	}
	if _, err := DecryptWithKey(key, ciphertext, []byte("bad"), "certificate:v1"); err == nil {
		t.Fatal("invalid GCM nonce was accepted")
	}
	if _, err := DecryptWithKey([]byte("bad"), ciphertext, nonce, "certificate:v1"); err == nil {
		t.Fatal("invalid AES key was accepted by decrypt")
	}
	tampered := append([]byte(nil), ciphertext...)
	tampered[len(tampered)-1] ^= 1
	if _, err := DecryptWithKey(key, tampered, nonce, "certificate:v1"); err == nil {
		t.Fatal("tampered ciphertext was accepted")
	}
	manager := &Manager{SignKey: ed25519.NewKeyFromSeed(bytes32(7))}
	signature, err := base64.RawURLEncoding.DecodeString(manager.Sign([]byte("snapshot")))
	if err != nil || !ed25519.Verify(manager.SignKey.Public().(ed25519.PublicKey), []byte("snapshot"), signature) {
		t.Fatalf("signature verification failed: %v", err)
	}
}

func TestCryptoPropagatesRandomnessAndFileWriteFailures(t *testing.T) {
	original := randomReader
	randomReader = failingRandomReader{}
	t.Cleanup(func() { randomReader = original })
	if _, _, err := EncryptWithKey([]byte("01234567890123456789012345678901"), []byte("value"), "aad"); err == nil {
		t.Fatal("encryption entropy failure was swallowed")
	}
	if _, err := Load(t.TempDir(), filepath.Join(t.TempDir(), "master.key"), filepath.Join(t.TempDir(), "signing.key")); err == nil {
		t.Fatal("key-generation entropy failure was swallowed")
	}
	randomReader = original
	directory := filepath.Join(t.TempDir(), "not-a-file")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreate(directory, 32); err == nil {
		t.Fatal("writing key material over a directory was accepted")
	}
}

func bytes32(value byte) []byte {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = value
	}
	return seed
}
