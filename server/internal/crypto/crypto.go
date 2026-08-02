package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type Manager struct {
	MasterKey      []byte
	RouterKey      []byte
	CertificateKey []byte
	SignKey        ed25519.PrivateKey
	KeyID          string
}

var randomReader io.Reader = rand.Reader

func Load(dataDir, masterPath, signingPath string) (*Manager, error) {
	master, err := loadOrCreate(masterPath, 32)
	if err != nil {
		return nil, fmt.Errorf("master key: %w", err)
	}
	signingRaw, err := loadOrCreate(signingPath, ed25519.PrivateKeySize)
	if err != nil {
		return nil, fmt.Errorf("config signing key: %w", err)
	}
	key := ed25519.PrivateKey(signingRaw)
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid config signing key")
	}
	routerKey, err := loadOrCreate(filepath.Join(dataDir, "router-snapshot.key"), 32)
	if err != nil {
		return nil, fmt.Errorf("router snapshot key: %w", err)
	}
	certificateKey, err := loadOrCreate(filepath.Join(dataDir, "certificate-wrapping.key"), 32)
	if err != nil {
		return nil, fmt.Errorf("certificate wrapping key: %w", err)
	}
	id := sha256.Sum256(key.Public().(ed25519.PublicKey))
	return &Manager{MasterKey: master, RouterKey: routerKey, CertificateKey: certificateKey, SignKey: key, KeyID: base64.RawURLEncoding.EncodeToString(id[:8])}, nil
}

func (m *Manager) Encrypt(plaintext []byte, aad string) (ciphertext, nonce []byte, err error) {
	return encryptWithKey(m.MasterKey, plaintext, aad)
}

func (m *Manager) Decrypt(ciphertext, nonce []byte, aad string) ([]byte, error) {
	return decryptWithKey(m.MasterKey, ciphertext, nonce, aad)
}

// EncryptWithKey is used only for a purpose-specific key such as the
// certificate wrapping key. Callers must never pass a key from user input.
func EncryptWithKey(key, plaintext []byte, aad string) (ciphertext, nonce []byte, err error) {
	return encryptWithKey(key, plaintext, aad)
}

func DecryptWithKey(key, ciphertext, nonce []byte, aad string) ([]byte, error) {
	return decryptWithKey(key, ciphertext, nonce, aad)
}

func encryptWithKey(key, plaintext []byte, aad string) (ciphertext, nonce []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(randomReader, nonce); err != nil {
		return nil, nil, err
	}
	return gcm.Seal(nil, nonce, plaintext, []byte(aad)), nonce, nil
}

func decryptWithKey(key, ciphertext, nonce []byte, aad string) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("invalid nonce length: got %d, want %d", len(nonce), gcm.NonceSize())
	}
	return gcm.Open(nil, nonce, ciphertext, []byte(aad))
}

func (m *Manager) Sign(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(m.SignKey, data))
}

func loadOrCreate(path string, size int) ([]byte, error) {
	if content, err := os.ReadFile(path); err == nil {
		if len(content) != size {
			return nil, fmt.Errorf("%s has invalid length", filepath.Base(path))
		}
		return content, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	content := make([]byte, size)
	if size == ed25519.PrivateKeySize {
		_, private, err := ed25519.GenerateKey(randomReader)
		if err != nil {
			return nil, err
		}
		copy(content, private)
	} else if _, err := io.ReadFull(randomReader, content); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		return nil, err
	}
	return content, nil
}
