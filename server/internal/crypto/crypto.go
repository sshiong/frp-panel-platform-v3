package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

type Manager struct {
	MasterKey             []byte
	MasterKeyVersion      int64
	RouterKey             []byte
	CertificateKey        []byte
	CertificateKeyVersion int64
	SignKey               ed25519.PrivateKey
	KeyID                 string
	mu                    sync.RWMutex
	masterPath            string
	masterKeys            map[int64][]byte
	certificatePath       string
	certificateKeys       map[int64][]byte
}

var randomReader io.Reader = rand.Reader

func Load(dataDir, masterPath, signingPath string) (*Manager, error) {
	master, masterVersion, masterKeys, err := loadKeyRing(masterPath, 32)
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
	certificatePath := filepath.Join(dataDir, "certificate-wrapping.key")
	certificateKey, certificateVersion, certificateKeys, err := loadKeyRing(certificatePath, 32)
	if err != nil {
		return nil, fmt.Errorf("certificate wrapping key: %w", err)
	}
	id := sha256.Sum256(key.Public().(ed25519.PublicKey))
	return &Manager{MasterKey: master, MasterKeyVersion: masterVersion, RouterKey: routerKey, CertificateKey: certificateKey, CertificateKeyVersion: certificateVersion, SignKey: key, KeyID: base64.RawURLEncoding.EncodeToString(id[:8]), masterPath: masterPath, masterKeys: masterKeys, certificatePath: certificatePath, certificateKeys: certificateKeys}, nil
}

func (m *Manager) Encrypt(plaintext []byte, aad string) (ciphertext, nonce []byte, err error) {
	m.mu.RLock()
	key := append([]byte(nil), m.MasterKey...)
	m.mu.RUnlock()
	return encryptWithKey(key, plaintext, aad)
}

func (m *Manager) Decrypt(ciphertext, nonce []byte, aad string) ([]byte, error) {
	keys := m.masterKeyVersions()
	var lastErr error
	for _, key := range keys {
		plaintext, err := decryptWithKey(key.key, ciphertext, nonce, aad)
		if err == nil {
			return plaintext, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		return nil, errors.New("master key is unavailable")
	}
	return nil, lastErr
}

// DecryptVersioned uses the recorded key version during a migration. A zero
// version retains the legacy fallback behavior for rows created before the
// key-version boundary was enforced.
func (m *Manager) DecryptVersioned(keyVersion int64, ciphertext, nonce []byte, aad string) ([]byte, error) {
	if keyVersion <= 0 {
		return m.Decrypt(ciphertext, nonce, aad)
	}
	m.mu.RLock()
	key, ok := m.masterKeys[keyVersion]
	if !ok && (keyVersion == m.MasterKeyVersion || (m.MasterKeyVersion <= 0 && keyVersion == 1)) {
		key = m.MasterKey
		ok = len(key) > 0
	}
	key = append([]byte(nil), key...)
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("master key version %d is unavailable", keyVersion)
	}
	return decryptWithKey(key, ciphertext, nonce, aad)
}

func (m *Manager) CurrentMasterKeyVersion() int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.MasterKeyVersion > 0 {
		return m.MasterKeyVersion
	}
	return 1
}

func (m *Manager) RotateMasterKey() (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if strings.TrimSpace(m.masterPath) == "" {
		return 0, errors.New("master key path is unavailable")
	}
	if m.masterKeys == nil {
		m.masterKeys = map[int64][]byte{}
	}
	if m.MasterKeyVersion <= 0 {
		m.MasterKeyVersion = 1
	}
	next := m.MasterKeyVersion + 1
	key, err := createExclusiveKey(m.masterPath+".v"+strconv.FormatInt(next, 10), 32)
	if err != nil {
		return 0, err
	}
	m.masterKeys[next] = append([]byte(nil), key...)
	m.MasterKey = append([]byte(nil), key...)
	m.MasterKeyVersion = next
	return next, nil
}

func (m *Manager) EncryptCertificate(plaintext []byte, aad string) (ciphertext, nonce []byte, err error) {
	m.mu.RLock()
	key := append([]byte(nil), m.CertificateKey...)
	m.mu.RUnlock()
	return encryptWithKey(key, plaintext, aad)
}

func (m *Manager) DecryptCertificate(keyVersion int64, ciphertext, nonce []byte, aad string) ([]byte, error) {
	if keyVersion > 0 && m.CertificateKeyVersion <= 0 && len(m.CertificateKey) > 0 && keyVersion == 1 {
		return decryptWithKey(append([]byte(nil), m.CertificateKey...), ciphertext, nonce, aad)
	}
	keys := m.certificateKeyVersions()
	if keyVersion > 0 {
		m.mu.RLock()
		key, ok := m.certificateKeys[keyVersion]
		if !ok && keyVersion == m.CertificateKeyVersion {
			key = m.CertificateKey
			ok = len(key) > 0
		}
		key = append([]byte(nil), key...)
		m.mu.RUnlock()
		if !ok {
			return nil, fmt.Errorf("certificate wrapping key version %d is unavailable", keyVersion)
		}
		return decryptWithKey(key, ciphertext, nonce, aad)
	}
	var lastErr error
	for _, key := range keys {
		plaintext, err := decryptWithKey(key.key, ciphertext, nonce, aad)
		if err == nil {
			return plaintext, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (m *Manager) CurrentCertificateKeyVersion() int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.CertificateKeyVersion > 0 {
		return m.CertificateKeyVersion
	}
	return 1
}

// MasterKeyRing returns the current master key followed by retained previous
// versions. It is intended for components that need to decrypt existing
// material during a migration while always encrypting with the current key.
func (m *Manager) MasterKeyRing() [][]byte {
	versions := m.masterKeyVersions()
	result := make([][]byte, 0, len(versions))
	for _, version := range versions {
		result = append(result, append([]byte(nil), version.key...))
	}
	return result
}

func (m *Manager) RotateCertificateKey() (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if strings.TrimSpace(m.certificatePath) == "" {
		return 0, errors.New("certificate wrapping key path is unavailable")
	}
	if m.certificateKeys == nil {
		m.certificateKeys = map[int64][]byte{}
	}
	if m.CertificateKeyVersion <= 0 {
		m.CertificateKeyVersion = 1
	}
	next := m.CertificateKeyVersion + 1
	key, err := createExclusiveKey(m.certificatePath+".v"+strconv.FormatInt(next, 10), 32)
	if err != nil {
		return 0, err
	}
	m.certificateKeys[next] = append([]byte(nil), key...)
	m.CertificateKey = append([]byte(nil), key...)
	m.CertificateKeyVersion = next
	return next, nil
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
	if content, err := os.ReadFile(path); err == nil { // #nosec G304 -- key path is a configured data-directory file
		if len(content) != size {
			return nil, fmt.Errorf("%s has invalid length", filepath.Base(path))
		}
		return content, nil
	} else if !os.IsNotExist(err) {
		return nil, err
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

type versionedKey struct {
	version int64
	key     []byte
}

func (m *Manager) masterKeyVersions() []versionedKey {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return orderedKeys(m.masterKeys, m.MasterKeyVersion, m.MasterKey)
}

func (m *Manager) certificateKeyVersions() []versionedKey {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return orderedKeys(m.certificateKeys, m.CertificateKeyVersion, m.CertificateKey)
}

func orderedKeys(keys map[int64][]byte, currentVersion int64, current []byte) []versionedKey {
	if len(keys) == 0 && len(current) == 0 {
		return nil
	}
	if currentVersion <= 0 {
		currentVersion = 1
	}
	versions := make([]int64, 0, len(keys)+1)
	seen := make(map[int64]struct{}, len(keys)+1)
	for version := range keys {
		versions = append(versions, version)
		seen[version] = struct{}{}
	}
	if _, ok := seen[currentVersion]; !ok && len(current) > 0 {
		versions = append(versions, currentVersion)
	}
	for index := 0; index < len(versions); index++ {
		for next := index + 1; next < len(versions); next++ {
			if versions[next] > versions[index] {
				versions[index], versions[next] = versions[next], versions[index]
			}
		}
	}
	result := make([]versionedKey, 0, len(versions))
	for _, version := range versions {
		key := keys[version]
		if version == currentVersion && len(current) > 0 {
			key = current
		}
		if len(key) == 0 {
			continue
		}
		result = append(result, versionedKey{version: version, key: append([]byte(nil), key...)})
	}
	return result
}

func loadKeyRing(path string, size int) ([]byte, int64, map[int64][]byte, error) {
	current, err := loadOrCreate(path, size)
	if err != nil {
		return nil, 0, nil, err
	}
	keys := map[int64][]byte{1: append([]byte(nil), current...)}
	currentVersion := int64(1)
	prefix := filepath.Base(path) + ".v"
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		return nil, 0, nil, err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		version, err := strconv.ParseInt(strings.TrimPrefix(entry.Name(), prefix), 10, 64)
		if err != nil || version <= 1 {
			continue
		}
		key, err := os.ReadFile(filepath.Join(filepath.Dir(path), entry.Name())) // #nosec G304 -- versioned key stays beside the configured key file
		if err != nil {
			return nil, 0, nil, err
		}
		if len(key) != size {
			return nil, 0, nil, fmt.Errorf("%s has invalid length", entry.Name())
		}
		keys[version] = append([]byte(nil), key...)
		if version > currentVersion {
			currentVersion = version
			current = append([]byte(nil), key...)
		}
	}
	return current, currentVersion, keys, nil
}

func createExclusiveKey(path string, size int) ([]byte, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	content := make([]byte, size)
	if _, err := io.ReadFull(randomReader, content); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- path is derived from the configured key file
	if err != nil {
		return nil, err
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	return content, nil
}
