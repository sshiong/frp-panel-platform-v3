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
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
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
	frpcVersion  string
	queue        chan func()
	mu           sync.RWMutex
	status       Status
	started      bool
	process      *runningProcess
	lastSnapshot *Snapshot
}

type runningProcess struct {
	cmd  *exec.Cmd
	done chan error
}

func New(dataDir, binary string) *Supervisor {
	return NewWithBinaryHash(dataDir, binary, "")
}

func NewWithBinaryHash(dataDir, binary, binarySHA256 string) *Supervisor {
	return NewWithBinaryHashAndVersion(dataDir, binary, binarySHA256, "0.68.0")
}

func NewWithBinaryHashAndVersion(dataDir, binary, binarySHA256, frpcVersion string) *Supervisor {
	mode := "simulated"
	if strings.TrimSpace(binary) != "" {
		mode = "real"
	}
	lastGoodAvailable := false
	if _, err := os.Stat(filepath.Join(dataDir, "state", "last-good-manifest.json")); err == nil {
		lastGoodAvailable = true
	}
	if strings.TrimSpace(frpcVersion) == "" {
		frpcVersion = "0.68.0"
	}
	s := &Supervisor{dataDir: dataDir, binary: binary, binarySHA256: strings.ToLower(strings.TrimSpace(binarySHA256)), frpcVersion: strings.TrimSpace(frpcVersion), queue: make(chan func(), 32), status: Status{State: "stopped", Mode: mode, LastGoodAvailable: lastGoodAvailable, UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano)}}
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

// RecoverOrphan runs once during client startup. A previous client process may
// have exited without stopping FRPC; in that case the PID marker is the only
// safe way to identify the process that this client owns. The command line is
// checked before any signal is sent so a reused PID is never treated as FRPC.
func (s *Supervisor) RecoverOrphan(ctx context.Context) error {
	result := make(chan error, 1)
	s.Enqueue(func() { result <- s.recoverOrphan(ctx) })
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Supervisor) recoverOrphan(ctx context.Context) error {
	pidPath := s.pidPath()
	encoded, err := os.ReadFile(pidPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// No valid Server Session exists during startup. Even without a
			// marker, remove stale runtime files; the manifest remains as a
			// non-secret read-only status record.
			return s.clearRecoveredRuntime()
		}
		return err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(encoded)))
	if err != nil || pid < 1 {
		return fmt.Errorf("invalid frpc pid marker")
	}
	if pid == os.Getpid() {
		return fmt.Errorf("refusing to terminate current client process")
	}

	// Development simulation has no configured binary with which to prove
	// ownership. Remove only the stale marker and secrets; never signal an
	// unknown process.
	if strings.TrimSpace(s.binary) == "" {
		if err := s.removePIDIf(pid); err != nil {
			return err
		}
		return s.clearRecoveredRuntime()
	}

	commandLine, commandErr := s.processCommandLine(ctx, pid)
	if commandErr != nil {
		process, findErr := os.FindProcess(pid)
		if findErr == nil && !processAlive(process) {
			if err := s.removePIDIf(pid); err != nil {
				return err
			}
			return s.clearRecoveredRuntime()
		}
		return fmt.Errorf("cannot inspect orphan frpc pid %d: %w", pid, commandErr)
	}
	if processCommandGone(commandLine) {
		// The process already exited. Runtime credentials are still unsafe to
		// retain after an unclean client shutdown.
		if err := s.removePIDIf(pid); err != nil {
			return err
		}
		return s.clearRecoveredRuntime()
	}
	configuredBinary, err := filepath.Abs(s.binary)
	if err != nil {
		return err
	}
	if !strings.Contains(commandLine, configuredBinary) {
		return fmt.Errorf("frpc pid %d command does not match configured binary", pid)
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	if err := s.terminateOrphan(ctx, process, pid); err != nil {
		return err
	}
	if err := s.removePIDIf(pid); err != nil {
		return err
	}
	return s.clearRecoveredRuntime()
}

func (s *Supervisor) processCommandLine(ctx context.Context, pid int) (string, error) {
	commandCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	output, err := exec.CommandContext(commandCtx, "ps", "-p", strconv.Itoa(pid), "-o", "command=").CombinedOutput()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func (s *Supervisor) terminateOrphan(ctx context.Context, process *os.Process, pid int) error {
	if err := process.Signal(os.Interrupt); err != nil && !errors.Is(err, os.ErrProcessDone) {
		if !processAlive(process) {
			return nil
		}
		return err
	}
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		if !processAlive(process) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			// Re-check the process identity immediately before force-killing it;
			// this closes the PID-reuse window as far as the platform permits.
			commandLine, err := s.processCommandLine(ctx, pid)
			if err != nil {
				if !processAlive(process) {
					return nil
				}
				return fmt.Errorf("cannot revalidate orphan frpc pid %d: %w", pid, err)
			}
			if processCommandGone(commandLine) {
				return nil
			}
			configuredBinary, absErr := filepath.Abs(s.binary)
			if absErr != nil {
				return absErr
			}
			if !strings.Contains(commandLine, configuredBinary) {
				return fmt.Errorf("frpc pid %d command changed before force kill: %q", pid, commandLine)
			}
			if err := process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				return err
			}
			return nil
		case <-ticker.C:
		}
	}
}

func processAlive(process *os.Process) bool {
	if process == nil {
		return false
	}
	err := process.Signal(syscall.Signal(0))
	return err == nil || errors.Is(err, syscall.EPERM)
}

func processCommandGone(commandLine string) bool {
	trimmed := strings.TrimSpace(commandLine)
	return trimmed == "" || strings.Contains(strings.ToLower(trimmed), "<defunct>")
}

func (s *Supervisor) clearRecoveredRuntime() error {
	if err := s.ClearRuntimeSecrets(); err != nil {
		return err
	}
	s.mu.Lock()
	s.status.State = "stopped"
	s.status.Mode = map[bool]string{true: "real", false: "simulated"}[s.binary != ""]
	s.status.PID = 0
	_, manifestErr := os.Stat(filepath.Join(s.dataDir, "state", "last-good-manifest.json"))
	s.status.LastGoodAvailable = manifestErr == nil
	s.status.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	s.mu.Unlock()
	return nil
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
	if !frpcVersionAtLeast(s.frpcVersion, "0.68.0") {
		return s.fail("FRPC_VERSION_UNSUPPORTED: platform requires FRPC 0.68.0 or newer")
	}
	if err := ctx.Err(); err != nil {
		return s.fail(err.Error())
	}
	configText := renderTOMLForVersion(snapshot, s.dataDir, s.frpcVersion)
	if err := s.writeRuntimeSecrets(snapshot); err != nil {
		return s.fail("FRPC_VERIFY_FAILED: " + err.Error())
	}
	if s.binary != "" {
		if err := checkLocalServices(ctx, snapshot.Payload); err != nil {
			return s.fail("LOCAL_SERVICE_UNAVAILABLE: " + err.Error())
		}
	}
	configDir := filepath.Join(s.dataDir, "config")
	tmpPath := filepath.Join(configDir, fmt.Sprintf("frpc.toml.tmp.%d", time.Now().UnixNano()))
	activePath := filepath.Join(configDir, "frpc.toml")
	lastGoodPath := filepath.Join(configDir, "frpc.last-good.toml")
	if err := writeDurableFile(tmpPath, []byte(configText), 0o600); err != nil {
		return s.fail("FRPC_VERIFY_FAILED: write temporary config")
	}
	defer os.Remove(tmpPath)
	if err := s.verify(ctx, tmpPath); err != nil {
		return s.fail("FRPC_VERIFY_FAILED: " + err.Error())
	}
	oldConfig, oldConfigErr := os.ReadFile(activePath)
	if oldConfigErr == nil {
		_ = atomicWriteDurable(lastGoodPath, oldConfig, 0o600)
	}
	if err := durableRename(tmpPath, activePath); err != nil {
		return s.fail("FRPC_VERIFY_FAILED: atomic replace")
	}
	useReload := s.reloadEligible(snapshot)
	runErr := error(nil)
	if useReload {
		runErr = s.reload(ctx)
	} else {
		runErr = s.restart(ctx)
	}
	if runErr != nil {
		if oldConfigErr == nil {
			_ = atomicWriteDurable(activePath, oldConfig, 0o600)
			if s.binary != "" {
				// A failed reload may have partially applied the new file; a
				// failed restart may have stopped the old process. Restarting
				// from the restored file makes the last-good guarantee explicit.
				if rollbackErr := s.restart(ctx); rollbackErr != nil {
					return s.fail("FRPC_RESTART_FAILED: " + runErr.Error() + "; rollback failed: " + rollbackErr.Error())
				}
			}
		}
		return s.fail("FRPC_RESTART_FAILED: " + runErr.Error())
	}
	manifest := map[string]interface{}{"config_version": snapshot.ConfigVersion, "config_hash": snapshot.ConfigHash, "applied_at": time.Now().UTC().Format(time.RFC3339Nano)}
	encoded, _ := json.MarshalIndent(manifest, "", "  ")
	_ = os.MkdirAll(filepath.Join(s.dataDir, "state"), 0o700)
	_ = atomicWriteDurable(filepath.Join(s.dataDir, "state", "last-good-manifest.json"), encoded, 0o600)
	s.mu.Lock()
	snapshotCopy := snapshot
	s.lastSnapshot = &snapshotCopy
	s.status.State = "running"
	s.status.AppliedVersion = snapshot.ConfigVersion
	s.status.ConfigHash = snapshot.ConfigHash
	s.status.LastGoodAvailable = true
	s.status.LastError = ""
	s.status.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	s.mu.Unlock()
	return nil
}

func (s *Supervisor) reloadEligible(snapshot Snapshot) bool {
	if s.binary == "" {
		return false
	}
	s.mu.RLock()
	previous := s.lastSnapshot
	active := s.process != nil
	s.mu.RUnlock()
	if previous == nil || !active || previous.UserID != snapshot.UserID || previous.SessionGeneration != snapshot.SessionGeneration {
		return false
	}
	for key, value := range previous.Payload {
		if key != "mappings" && !reflect.DeepEqual(value, snapshot.Payload[key]) {
			return false
		}
	}
	for key, value := range snapshot.Payload {
		if key != "mappings" && !reflect.DeepEqual(value, previous.Payload[key]) {
			return false
		}
	}
	return true
}

func (s *Supervisor) reload(ctx context.Context) error {
	if err := s.verifyBinary(); err != nil {
		return err
	}
	commandCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(commandCtx, s.binary, "reload", "-c", filepath.Join(s.dataDir, "config", "frpc.toml"))
	cmd.Stdin = nil
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("frpc reload failed: %w", err)
	}
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
	if err := s.writePID(cmd.Process.Pid); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return fmt.Errorf("write frpc pid: %w", err)
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
		_ = s.removePIDIf(cmd.Process.Pid)
		s.mu.Lock()
		if s.process == running {
			s.process = nil
			s.status.PID = 0
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
	// The last applied snapshot contains the runtime-only FRP credentials that
	// App injected immediately before Apply. Clearing files is not sufficient:
	// logout, session replacement, and server switching must also remove those
	// values from the Supervisor's in-memory reload state.
	s.mu.Lock()
	if s.lastSnapshot != nil {
		for _, key := range []string{"frp_secret", "frp_user_secret", "runtime_credential", "frps_transport_secret"} {
			delete(s.lastSnapshot.Payload, key)
		}
		s.lastSnapshot = nil
	}
	s.mu.Unlock()
	return nil
}

func (s *Supervisor) writeRuntimeSecrets(snapshot Snapshot) error {
	transportSecret := payloadString(snapshot.Payload, "frps_transport_secret")
	if transportSecret == "" {
		// Development snapshots created before the deployment transport-secret
		// split can still be verified; production Server login always supplies
		// the dedicated frps transport value.
		transportSecret = payloadString(snapshot.Payload, "frp_secret")
	}
	userSecret := payloadString(snapshot.Payload, "frp_user_secret")
	if userSecret == "" {
		userSecret = payloadString(snapshot.Payload, "frp_secret")
	}
	runtimeCredential := payloadString(snapshot.Payload, "runtime_credential")
	if transportSecret == "" || userSecret == "" || runtimeCredential == "" {
		return fmt.Errorf("runtime FRP secrets are incomplete")
	}
	secretDir := filepath.Join(s.dataDir, "runtime", "secrets")
	if err := os.MkdirAll(secretDir, 0o700); err != nil {
		return err
	}
	for name, value := range map[string]string{
		"transport-token": transportSecret,
		"user-frp-secret": userSecret,
		"runtime-token":   runtimeCredential,
	} {
		if err := atomicWriteDurable(filepath.Join(secretDir, name), []byte(value+"\n"), 0o600); err != nil {
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
		_ = s.removePIDIf(process.cmd.Process.Pid)
		return nil
	case <-time.After(2 * time.Second):
		_ = process.cmd.Process.Kill()
		select {
		case <-process.done:
			_ = s.removePIDIf(process.cmd.Process.Pid)
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (s *Supervisor) pidPath() string {
	return filepath.Join(s.dataDir, "state", "frpc.pid")
}

func (s *Supervisor) writePID(pid int) error {
	return atomicWriteDurable(s.pidPath(), []byte(strconv.Itoa(pid)+"\n"), 0o600)
}

func writeDurableFile(path string, content []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func atomicWriteDurable(path string, content []byte, mode os.FileMode) error {
	tmpPath := fmt.Sprintf("%s.tmp.%d", path, time.Now().UnixNano())
	defer os.Remove(tmpPath)
	if err := writeDurableFile(tmpPath, content, mode); err != nil {
		return err
	}
	return durableRename(tmpPath, path)
}

func durableRename(source, target string) error {
	if err := os.Rename(source, target); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(target))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (s *Supervisor) removePIDIf(pid int) error {
	encoded, err := os.ReadFile(s.pidPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if strings.TrimSpace(string(encoded)) != strconv.Itoa(pid) {
		return nil
	}
	if err := os.Remove(s.pidPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
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
func renderTOMLForVersion(snapshot Snapshot, dataDir, frpcVersion string) string {
	var b strings.Builder
	b.WriteString("# Generated by FRP Panel Client; do not edit.\n")
	fmt.Fprintf(&b, "# config_version = %d\n", snapshot.ConfigVersion)
	payload, _ := json.Marshal(snapshot.Payload)
	sum := sha256.Sum256(payload)
	fmt.Fprintf(&b, "# payload_sha256 = %s\n\n", hex.EncodeToString(sum[:]))
	serverAddr := payloadString(snapshot.Payload, "frps_public_host")
	if serverAddr == "" {
		serverAddr = payloadString(snapshot.Payload, "server_addr")
	}
	serverPort := payloadInt(snapshot.Payload, "frps_public_port", 7000)
	username := payloadString(snapshot.Payload, "frp_username")
	if username != "" {
		fmt.Fprintf(&b, "user = %s\n", tomlString(username))
	}
	runtimeCredential := payloadString(snapshot.Payload, "runtime_credential")
	transportSecret := payloadString(snapshot.Payload, "frps_transport_secret")
	if transportSecret == "" {
		transportSecret = payloadString(snapshot.Payload, "frp_secret")
	}
	transportPath := filepath.Join("runtime", "secrets", "transport-token")
	if strings.TrimSpace(dataDir) != "" {
		transportPath = filepath.Join(dataDir, "runtime", "secrets", "transport-token")
	}
	userSecret := payloadString(snapshot.Payload, "frp_user_secret")
	if userSecret == "" {
		userSecret = payloadString(snapshot.Payload, "frp_secret")
	}
	fmt.Fprintf(&b, "serverAddr = %s\nserverPort = %d\nloginFailExit = false\nauth.method = \"token\"\n", tomlString(serverAddr), serverPort)
	if frpcVersionAtLeast(frpcVersion, "0.64.0") {
		fmt.Fprintf(&b, "auth.tokenSource.type = \"file\"\nauth.tokenSource.file.path = %s\n", tomlString(transportPath))
	} else {
		// This branch exists only for source-level compatibility with legacy
		// tooling. Supervisor.Apply rejects versions below the platform
		// minimum, so production never embeds the native token in TOML.
		fmt.Fprintf(&b, "auth.token = %s\n", tomlString(transportSecret))
	}
	fmt.Fprintf(&b, "metadatas = { frp_runtime_credential = %s, session_generation = %s, frp_user_secret = %s }\n\n", tomlString(runtimeCredential), tomlString(strconv.FormatInt(snapshot.SessionGeneration, 10)), tomlString(userSecret))
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
			fmt.Fprintf(&b, "metadatas = { mapping_id = %s, mapping_revision = %s }\n\n", tomlString(mappingID), tomlString(strconv.Itoa(payloadInt(item, "revision", 1))))
		}
	}
	return b.String()
}

func frpcVersionAtLeast(actual, minimum string) bool {
	parse := func(value string) ([3]int, bool) {
		var result [3]int
		parts := strings.Split(strings.TrimSpace(value), ".")
		if len(parts) < 2 {
			return result, false
		}
		for index := 0; index < len(result) && index < len(parts); index++ {
			part := parts[index]
			for offset, character := range part {
				if character < '0' || character > '9' {
					part = part[:offset]
					break
				}
			}
			if part == "" {
				return result, false
			}
			parsed, err := strconv.Atoi(part)
			if err != nil {
				return result, false
			}
			result[index] = parsed
		}
		return result, true
	}
	actualVersion, actualOK := parse(actual)
	minimumVersion, minimumOK := parse(minimum)
	if !actualOK || !minimumOK {
		return false
	}
	for index := range actualVersion {
		if actualVersion[index] != minimumVersion[index] {
			return actualVersion[index] > minimumVersion[index]
		}
	}
	return true
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
