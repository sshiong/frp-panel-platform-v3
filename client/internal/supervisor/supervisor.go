package supervisor

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Snapshot struct {
	SchemaVersion     string                 `json:"schema_version"`
	ConfigVersion     int64                  `json:"config_version"`
	UserID            string                 `json:"user_id"`
	SessionGeneration int64                  `json:"session_generation"`
	IssuedAt          string                 `json:"issued_at"`
	ExpiresAt         string                 `json:"expires_at"`
	ConfigHash        string                 `json:"config_hash"`
	SigningKeyID      string                 `json:"signing_key_id"`
	Signature         string                 `json:"signature"`
	Payload           map[string]interface{} `json:"payload"`
}

func VerifySnapshot(snapshot Snapshot, publicKey ed25519.PublicKey) bool {
	if snapshot.Signature == "" || len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	signature, err := base64.RawURLEncoding.DecodeString(snapshot.Signature)
	if err != nil {
		return false
	}
	unsigned := snapshot
	unsigned.Signature = ""
	encoded, err := json.Marshal(unsigned)
	if err != nil {
		return false
	}
	return ed25519.Verify(publicKey, encoded, signature)
}

type Status struct {
	State             string `json:"state"`
	Mode              string `json:"mode"`
	PID               int    `json:"pid"`
	DesiredVersion    int64  `json:"desired_config_version"`
	AppliedVersion    int64  `json:"applied_config_version"`
	ConfigHash        string `json:"config_hash"`
	LastGoodAvailable bool   `json:"last_good_available"`
	LastError         string `json:"last_error,omitempty"`
	UpdatedAt         string `json:"updated_at"`
}

type Supervisor struct {
	dataDir string
	binary  string
	queue   chan func()
	mu      sync.RWMutex
	status  Status
	started bool
}

func New(dataDir, binary string) *Supervisor {
	s := &Supervisor{dataDir: dataDir, binary: binary, queue: make(chan func(), 32), status: Status{State: "stopped", Mode: "simulated", UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano)}}
	go func() {
		for operation := range s.queue {
			operation()
		}
	}()
	return s
}

func (s *Supervisor) Enqueue(operation func()) {
	select {
	case s.queue <- operation:
	default:
		go operation()
	}
}

func (s *Supervisor) Apply(ctx context.Context, snapshot Snapshot) error {
	result := make(chan error, 1)
	s.Enqueue(func() { result <- s.apply(ctx, snapshot) })
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Supervisor) apply(ctx context.Context, snapshot Snapshot) error {
	s.mu.Lock()
	s.status.State = "applying"
	s.status.DesiredVersion = snapshot.ConfigVersion
	s.status.LastError = ""
	s.status.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	s.mu.Unlock()
	if snapshot.SchemaVersion != "v1" || snapshot.ConfigVersion < 0 || snapshot.UserID == "" || snapshot.SessionGeneration < 1 {
		return s.fail("FRPC_VERIFY_FAILED: invalid signed config metadata")
	}
	if err := ctx.Err(); err != nil {
		return s.fail(err.Error())
	}
	configText := renderTOML(snapshot)
	configDir := filepath.Join(s.dataDir, "config")
	tmpPath := filepath.Join(configDir, fmt.Sprintf("frpc.toml.tmp.%d", time.Now().UnixNano()))
	activePath := filepath.Join(configDir, "frpc.toml")
	lastGoodPath := filepath.Join(configDir, "frpc.last-good.toml")
	if err := os.WriteFile(tmpPath, []byte(configText), 0o600); err != nil {
		return s.fail("FRPC_VERIFY_FAILED: write temporary config")
	}
	defer os.Remove(tmpPath)
	if err := s.verify(ctx, tmpPath); err != nil {
		return s.fail("FRPC_VERIFY_FAILED: " + err.Error())
	}
	if old, err := os.ReadFile(activePath); err == nil {
		_ = os.WriteFile(lastGoodPath, old, 0o600)
	}
	if err := os.Rename(tmpPath, activePath); err != nil {
		return s.fail("FRPC_VERIFY_FAILED: atomic replace")
	}
	manifest := map[string]interface{}{"config_version": snapshot.ConfigVersion, "config_hash": snapshot.ConfigHash, "applied_at": time.Now().UTC().Format(time.RFC3339Nano)}
	encoded, _ := json.MarshalIndent(manifest, "", "  ")
	_ = os.WriteFile(filepath.Join(s.dataDir, "state", "last-good-manifest.json"), encoded, 0o600)
	if err := s.restart(ctx); err != nil {
		if old, readErr := os.ReadFile(lastGoodPath); readErr == nil {
			_ = os.WriteFile(activePath, old, 0o600)
		}
		return s.fail("FRPC_RESTART_FAILED: " + err.Error())
	}
	s.mu.Lock()
	s.status.State = "running"
	s.status.AppliedVersion = snapshot.ConfigVersion
	s.status.ConfigHash = snapshot.ConfigHash
	s.status.LastGoodAvailable = true
	s.status.LastError = ""
	s.status.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	s.mu.Unlock()
	return nil
}

func (s *Supervisor) verify(ctx context.Context, path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("config path is empty")
	}
	if s.binary == "" {
		return nil
	}
	commandCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(commandCtx, s.binary, "verify", "--config", path)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("fixed frpc verify failed: %s", sanitize(string(output)))
	}
	return nil
}

func (s *Supervisor) restart(ctx context.Context) error {
	if s.binary == "" {
		s.mu.Lock()
		s.status.Mode = "simulated"
		s.status.PID = 0
		s.mu.Unlock()
		return nil
	}
	// A production adapter owns the process handle and validates PID/start time. The
	// development supervisor keeps the command surface fixed to this one binary.
	commandCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(commandCtx, s.binary, "--config", filepath.Join(s.dataDir, "config", "frpc.toml"))
	if err := cmd.Start(); err != nil {
		return err
	}
	s.mu.Lock()
	s.status.Mode = "real"
	s.status.PID = cmd.Process.Pid
	s.started = true
	s.mu.Unlock()
	return nil
}

func (s *Supervisor) Stop(ctx context.Context) error {
	result := make(chan error, 1)
	s.Enqueue(func() {
		s.mu.Lock()
		s.status.State = "stopped"
		s.status.PID = 0
		s.status.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		s.mu.Unlock()
		result <- nil
	})
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (s *Supervisor) Status() Status { s.mu.RLock(); defer s.mu.RUnlock(); return s.status }
func (s *Supervisor) ClearRuntimeSecrets() error {
	return os.RemoveAll(filepath.Join(s.dataDir, "runtime", "secrets"))
}

func (s *Supervisor) fail(message string) error {
	s.mu.Lock()
	s.status.State = "config_error"
	s.status.LastError = sanitize(message)
	s.status.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	s.mu.Unlock()
	return fmt.Errorf("%s", message)
}
func renderTOML(snapshot Snapshot) string {
	var b strings.Builder
	b.WriteString("# Generated by FRP Panel Client; do not edit.\n")
	fmt.Fprintf(&b, "# config_version = %d\n", snapshot.ConfigVersion)
	payload, _ := json.Marshal(snapshot.Payload)
	sum := sha256.Sum256(payload)
	fmt.Fprintf(&b, "# payload_sha256 = %s\n\n", hex.EncodeToString(sum[:]))
	b.WriteString("serverAddr = \"runtime-secret\"\nserverPort = 7000\nloginFailExit = false\n\n")
	if mappings, ok := snapshot.Payload["mappings"].([]interface{}); ok {
		for index, raw := range mappings {
			item, _ := raw.(map[string]interface{})
			fmt.Fprintf(&b, "[proxies.%d]\nname = \"mapping-%v\"\ntype = \"%v\"\nlocalIP = \"%v\"\nlocalPort = %v\nremotePort = %v\n\n", index, item["mapping_id"], item["proxy_type"], item["local_ip"], item["local_port"], item["remote_port"])
		}
	}
	return b.String()
}
func sanitize(value string) string {
	value = strings.ReplaceAll(value, "Bearer ", "Bearer [redacted]")
	if len(value) > 240 {
		return value[:240]
	}
	return value
}
