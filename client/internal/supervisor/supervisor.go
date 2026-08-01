package supervisor

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ricardo/frp-panel-platform/client/internal/healthcheck"
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
	dataDir      string
	binary       string
	binarySHA256 string
	queue        chan func()
	mu           sync.RWMutex
	status       Status
	started      bool
	process      *runningProcess
}

type runningProcess struct {
	cmd  *exec.Cmd
	done chan error
}

func New(dataDir, binary string) *Supervisor {
	return NewWithBinaryHash(dataDir, binary, "")
}

func NewWithBinaryHash(dataDir, binary, binarySHA256 string) *Supervisor {
	s := &Supervisor{dataDir: dataDir, binary: binary, binarySHA256: strings.ToLower(strings.TrimSpace(binarySHA256)), queue: make(chan func(), 32), status: Status{State: "stopped", Mode: "simulated", UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano)}}
	go func() {
		for operation := range s.queue {
			operation()
		}
	}()
	return s
}

func (s *Supervisor) Enqueue(operation func()) {
	// Never execute a process/config mutation outside the single Supervisor
	// queue. Backpressure is safer than allowing a second goroutine to race a
	// restart, rollback, or secret cleanup.
	s.queue <- operation
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
	if s.binary != "" {
		if err := checkLocalServices(ctx, snapshot.Payload); err != nil {
			return s.fail("LOCAL_SERVICE_UNAVAILABLE: " + err.Error())
		}
	}
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

func checkLocalServices(ctx context.Context, payload map[string]interface{}) error {
	mappings, ok := payload["mappings"].([]interface{})
	if !ok {
		return nil
	}
	for _, raw := range mappings {
		item, ok := raw.(map[string]interface{})
		if !ok {
			return fmt.Errorf("invalid mapping payload")
		}
		proxyType := payloadString(item, "proxy_type")
		host := payloadString(item, "local_ip")
		port := payloadInt(item, "local_port", 0)
		if err := healthcheck.Check(ctx, proxyType, host, port); err != nil {
			return fmt.Errorf("%s %s:%d: %w", proxyType, host, port, err)
		}
	}
	return nil
}

func (s *Supervisor) verify(ctx context.Context, path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("config path is empty")
	}
	if s.binary == "" {
		return nil
	}
	if err := s.verifyBinary(); err != nil {
		return err
	}
	commandCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(commandCtx, s.binary, "verify", "-c", path)
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
	if err := s.verifyBinary(); err != nil {
		return err
	}
	if err := s.stopProcess(ctx); err != nil {
		return err
	}
	// The FRPC process outlives the short apply request; Stop owns its lifetime.
	cmd := exec.Command(s.binary, "-c", filepath.Join(s.dataDir, "config", "frpc.toml"))
	cmd.Stdin = nil
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return err
	}
	running := &runningProcess{cmd: cmd, done: make(chan error, 1)}
	s.mu.Lock()
	s.process = running
	s.status.Mode = "real"
	s.status.PID = cmd.Process.Pid
	s.started = true
	s.mu.Unlock()
	go func() {
		err := cmd.Wait()
		running.done <- err
		s.mu.Lock()
		if s.process == running {
			s.process = nil
			if s.status.State == "running" {
				s.status.State = "offline"
				s.status.LastError = sanitize("FRPC exited")
				s.status.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
			}
		}
		s.mu.Unlock()
	}()
	select {
	case err := <-running.done:
		if err != nil {
			return fmt.Errorf("frpc exited during start: %w", err)
		}
		return errors.New("frpc exited during start")
	default:
	}
	return nil
}

func (s *Supervisor) Stop(ctx context.Context) error {
	result := make(chan error, 1)
	s.Enqueue(func() {
		err := s.stopProcess(ctx)
		s.mu.Lock()
		s.status.State = "stopped"
		s.status.PID = 0
		s.status.LastGoodAvailable = false
		s.status.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		s.mu.Unlock()
		result <- err
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
	for _, path := range []string{filepath.Join(s.dataDir, "runtime", "secrets"), filepath.Join(s.dataDir, "config", "frpc.toml"), filepath.Join(s.dataDir, "config", "frpc.last-good.toml")} {
		if err := os.RemoveAll(path); err != nil {
			return err
		}
	}
	return nil
}

func (s *Supervisor) stopProcess(ctx context.Context) error {
	s.mu.Lock()
	process := s.process
	s.process = nil
	s.mu.Unlock()
	if process == nil || process.cmd.Process == nil {
		return nil
	}
	_ = process.cmd.Process.Signal(os.Interrupt)
	select {
	case <-process.done:
		return nil
	case <-time.After(2 * time.Second):
		_ = process.cmd.Process.Kill()
		select {
		case <-process.done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (s *Supervisor) verifyBinary() error {
	if s.binary == "" || s.binarySHA256 == "" {
		return nil
	}
	file, err := os.Open(s.binary)
	if err != nil {
		return err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	if actual != s.binarySHA256 {
		return fmt.Errorf("frpc binary sha256 mismatch")
	}
	return nil
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
	serverAddr := payloadString(snapshot.Payload, "server_addr")
	if serverAddr == "" {
		serverAddr = payloadString(snapshot.Payload, "frps_public_host")
	}
	serverPort := payloadInt(snapshot.Payload, "frps_public_port", 7000)
	fmt.Fprintf(&b, "serverAddr = %s\nserverPort = %d\nloginFailExit = false\nauth.method = \"token\"\nauth.token = %s\n\n", tomlString(serverAddr), serverPort, tomlString(payloadString(snapshot.Payload, "frp_secret")))
	runtimeCredential := payloadString(snapshot.Payload, "runtime_credential")
	if mappings, ok := snapshot.Payload["mappings"].([]interface{}); ok {
		for _, raw := range mappings {
			item, _ := raw.(map[string]interface{})
			mappingID := fmt.Sprint(item["mapping_id"])
			fmt.Fprintf(&b, "[[proxies]]\nname = %s\ntype = %s\nlocalIP = %s\nlocalPort = %d\n", tomlString("mapping-"+mappingID), tomlString(fmt.Sprint(item["proxy_type"])), tomlString(fmt.Sprint(item["local_ip"])), payloadInt(item, "local_port", 0))
			if item["proxy_type"] != "http" {
				fmt.Fprintf(&b, "remotePort = %d\n", payloadInt(item, "remote_port", 0))
			}
			if domains, ok := item["custom_domains"].([]interface{}); ok && len(domains) > 0 {
				values := make([]string, 0, len(domains))
				for _, domain := range domains {
					values = append(values, tomlString(fmt.Sprint(domain)))
				}
				fmt.Fprintf(&b, "customDomains = [%s]\n", strings.Join(values, ", "))
			}
			fmt.Fprintf(&b, "metadatas = { mapping_id = %s, frp_runtime_credential = %s }\n\n", tomlString(mappingID), tomlString(runtimeCredential))
		}
	}
	return b.String()
}

func payloadString(payload map[string]interface{}, key string) string {
	value, _ := payload[key].(string)
	return value
}

func payloadInt(payload map[string]interface{}, key string, fallback int) int {
	switch value := payload[key].(type) {
	case float64:
		return int(value)
	case int:
		return value
	case int64:
		return int(value)
	}
	return fallback
}

func tomlString(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}
func sanitize(value string) string {
	value = strings.ReplaceAll(value, "Bearer ", "Bearer [redacted]")
	if len(value) > 240 {
		return value[:240]
	}
	return value
}
