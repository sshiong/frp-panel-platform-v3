package router

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type Route struct {
	Hostname     string `json:"hostname"`
	Target       string `json:"target"`
	HTTPSMode    string `json:"https_mode"`
	HTTPRedirect bool   `json:"http_redirect"`
	Status       string `json:"status"`
}
type Snapshot struct {
	SchemaVersion  string  `json:"schema_version"`
	Version        int64   `json:"version"`
	ControlRoutes  []Route `json:"control_routes"`
	BusinessRoutes []Route `json:"business_routes"`
	Hash           string  `json:"hash"`
	HMAC           string  `json:"hmac"`
	GeneratedAt    string  `json:"generated_at"`
}

func Build(version int64, control, business []Route, key []byte) (Snapshot, error) {
	snapshot := Snapshot{SchemaVersion: "v1", Version: version, ControlRoutes: control, BusinessRoutes: business, GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	unsigned, _ := json.Marshal(snapshot)
	sum := sha256.Sum256(unsigned)
	snapshot.Hash = hex.EncodeToString(sum[:])
	unsigned, _ = json.Marshal(snapshot)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(unsigned)
	snapshot.HMAC = hex.EncodeToString(mac.Sum(nil))
	return snapshot, nil
}
func Verify(snapshot Snapshot, key []byte) bool {
	h := snapshot.HMAC
	snapshot.HMAC = ""
	if !verifyHash(snapshot) {
		return false
	}
	unsigned, _ := json.Marshal(snapshot)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(unsigned)
	return hmac.Equal([]byte(h), []byte(hex.EncodeToString(mac.Sum(nil))))
}

func verifyHash(snapshot Snapshot) bool {
	declared := snapshot.Hash
	snapshot.Hash = ""
	snapshot.HMAC = ""
	unsigned, err := json.Marshal(snapshot)
	if err != nil {
		return false
	}
	sum := sha256.Sum256(unsigned)
	return declared == hex.EncodeToString(sum[:])
}
func AtomicWrite(path string, snapshot Snapshot) error {
	if snapshot.SchemaVersion != "v1" {
		return fmt.Errorf("unsupported router snapshot schema")
	}
	encoded, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + fmt.Sprintf(".tmp.%d", time.Now().UnixNano())
	keepTemp := true
	defer func() {
		if keepTemp {
			_ = os.Remove(tmp)
		}
	}()
	file, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) // #nosec G304 -- temporary snapshot path is generated from the configured target
	if err != nil {
		return err
	}
	if _, err := file.Write(encoded); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	keepTemp = false
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
