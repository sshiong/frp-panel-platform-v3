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
	unsigned, _ := json.Marshal(snapshot)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(unsigned)
	return hmac.Equal([]byte(h), []byte(hex.EncodeToString(mac.Sum(nil))))
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
	if err := os.WriteFile(tmp, encoded, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
