package supervisor

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestVerifySnapshot(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	snapshot := Snapshot{SchemaVersion: "v1", ConfigVersion: 1, UserID: "user", SessionGeneration: 2, ConfigHash: "hash", SigningKeyID: "key", Payload: map[string]interface{}{"mappings": []interface{}{}}}
	unsigned := snapshot
	encoded, _ := json.Marshal(unsigned)
	snapshot.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, encoded))
	if !VerifySnapshot(snapshot, public) {
		t.Fatal("signed config should verify")
	}
	snapshot.ConfigVersion = 2
	if VerifySnapshot(snapshot, public) {
		t.Fatal("tampered config must fail")
	}
}

func TestStartupLoadsLastGoodAvailability(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "state", "last-good-manifest.json"), []byte(`{"config_version":7}`), 0o600); err != nil {
		t.Fatal(err)
	}
	status := NewWithBinaryHash(root, "/usr/local/bin/frpc", "").Status()
	if !status.LastGoodAvailable || status.State != "stopped" || status.Mode != "real" {
		t.Fatalf("last-good state should be readable before login: %#v", status)
	}
}

func TestRealBinaryVerifyRestartAndStop(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "config"), 0o700); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(root, "fake-frpc")
	script := []byte("#!/bin/sh\nif [ \"$1\" = \"verify\" ] || [ \"$1\" = \"reload\" ]; then exit 0; fi\ntrap 'exit 0' INT TERM\nwhile true; do sleep 1; done\n")
	if err := os.WriteFile(binary, script, 0o700); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(script)
	supervisor := NewWithBinaryHash(root, binary, hex.EncodeToString(digest[:]))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("local listener unavailable: %v", err)
	}
	defer listener.Close()
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			_ = connection.Close()
		}
	}()
	localPort := listener.Addr().(*net.TCPAddr).Port
	snapshot := Snapshot{SchemaVersion: "v1", ConfigVersion: 1, UserID: "user-1", SessionGeneration: 1, Payload: map[string]interface{}{"frps_public_host": "frp.example.com", "frps_public_port": 7000, "frp_secret": "secret", "frp_username": "user-1", "runtime_credential": "runtime", "mappings": []interface{}{map[string]interface{}{"mapping_id": "mapping-1", "proxy_type": "tcp", "local_ip": "127.0.0.1", "local_port": localPort, "remote_port": 6000}}}}
	if err := supervisor.Apply(t.Context(), snapshot); err != nil {
		t.Fatal(err)
	}
	status := supervisor.Status()
	if status.State != "running" || status.Mode != "real" || status.PID == 0 {
		t.Fatalf("unexpected running status: %#v", status)
	}
	config, err := os.ReadFile(filepath.Join(root, "config", "frpc.toml"))
	if err != nil || string(config) == "" {
		t.Fatalf("config was not written: %v", err)
	}
	secondSnapshot := Snapshot{SchemaVersion: "v1", ConfigVersion: 2, UserID: "user-1", SessionGeneration: 1, ConfigHash: "hash-2", Payload: map[string]interface{}{"frps_public_host": "frp.example.com", "frps_public_port": 7000, "frp_secret": "secret", "frp_username": "user-1", "runtime_credential": "runtime", "mappings": []interface{}{map[string]interface{}{"mapping_id": "mapping-1", "proxy_type": "tcp", "local_ip": "127.0.0.1", "local_port": localPort, "remote_port": 6001}}}}
	if err := supervisor.Apply(t.Context(), secondSnapshot); err != nil {
		t.Fatal(err)
	}
	if reloaded := supervisor.Status(); reloaded.PID != status.PID || reloaded.AppliedVersion != 2 {
		t.Fatalf("proxy-only update should reload in place: before=%#v after=%#v", status, reloaded)
	}
	if err := supervisor.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for supervisor.Status().State != "stopped" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if status := supervisor.Status(); status.State != "stopped" || status.PID != 0 {
		t.Fatalf("unexpected stopped status: %#v", status)
	}
}

func TestRenderTOMLIsAcceptedByFixedFRPCWhenConfigured(t *testing.T) {
	binary := os.Getenv("FRPC_VERIFY_BINARY")
	if binary == "" {
		t.Skip("set FRPC_VERIFY_BINARY to run fixed FRPC config compatibility verification")
	}
	version := os.Getenv("FRPC_VERIFY_VERSION")
	if version == "" {
		version = "0.68.0"
	}
	root := t.TempDir()
	remotePort := 6000
	snapshot := Snapshot{ConfigVersion: 7, SessionGeneration: 3, Payload: map[string]interface{}{
		"server_addr":        "panel.example.com",
		"frps_public_host":   "frp.example.com",
		"frps_public_port":   7000,
		"frp_username":       "user-alice",
		"frp_secret":         "frp-secret",
		"runtime_credential": "runtime-credential",
		"mappings": []interface{}{map[string]interface{}{
			"mapping_id":     "mapping-1",
			"proxy_type":     "tcp",
			"local_ip":       "127.0.0.1",
			"local_port":     8080,
			"remote_port":    remotePort,
			"revision":       2,
			"custom_domains": []interface{}{},
		}},
	}}
	configPath := filepath.Join(root, "frpc.toml")
	supervisor := NewWithBinaryHashAndVersion(root, binary, "", version)
	if err := supervisor.writeRuntimeSecrets(snapshot); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(renderTOMLForVersion(snapshot, root, version)), 0o600); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), `serverAddr = "panel.example.com"`) || !strings.Contains(string(encoded), `serverAddr = "frp.example.com"`) {
		t.Fatalf("generated FRPC config used the Server Panel address instead of FRPS public host:\n%s", encoded)
	}
	output, err := exec.Command(binary, "verify", "-c", configPath).CombinedOutput()
	if err != nil {
		t.Fatalf("fixed FRPC rejected generated TOML: %v\n%s", err, output)
	}
}

func TestReloadFailureRestoresAndRestartsLastGood(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "config"), 0o700); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(root, "fake-frpc")
	script := []byte("#!/bin/sh\nif [ \"$1\" = \"verify\" ]; then exit 0; fi\nif [ \"$1\" = \"reload\" ]; then exit 1; fi\ntrap 'exit 0' INT TERM\nwhile true; do sleep 1; done\n")
	if err := os.WriteFile(binary, script, 0o700); err != nil {
		t.Fatal(err)
	}
	s := New(root, binary)
	basePayload := map[string]interface{}{"frps_public_host": "frp.example.com", "frps_public_port": 7000, "frp_secret": "secret", "frp_username": "user-1", "runtime_credential": "runtime", "mappings": []interface{}{}}
	first := Snapshot{SchemaVersion: "v1", ConfigVersion: 1, UserID: "user-1", SessionGeneration: 1, ConfigHash: "hash-1", Payload: basePayload}
	if err := s.Apply(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	second := Snapshot{SchemaVersion: "v1", ConfigVersion: 2, UserID: "user-1", SessionGeneration: 1, ConfigHash: "hash-2", Payload: basePayload}
	if err := s.Apply(t.Context(), second); err == nil {
		t.Fatal("failed reload should be reported")
	}
	config, err := os.ReadFile(filepath.Join(root, "config", "frpc.toml"))
	if err != nil || !strings.Contains(string(config), "config_version = 1") {
		t.Fatalf("last-good config was not restored: %q err=%v", config, err)
	}
	if status := s.Status(); status.PID == 0 {
		t.Fatalf("last-good process should be restarted: %#v", status)
	}
	if err := s.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestRecoverOrphanStopsOwnedProcessAndClearsRuntime(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "config"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "runtime", "secrets"), 0o700); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(root, "fake-frpc")
	script := []byte("#!/bin/sh\ntrap 'exit 0' INT TERM\nwhile true; do sleep 1; done\n")
	if err := os.WriteFile(binary, script, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "config", "frpc.toml")
	secretPath := filepath.Join(root, "runtime", "secrets", "runtime.token")
	if err := os.WriteFile(configPath, []byte("auth.token = \\\"secret\\\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secretPath, []byte("runtime-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "-c", configPath)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "state", "frpc.pid"), []byte(strconv.Itoa(cmd.Process.Pid)+"\n"), 0o600); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatal(err)
	}

	s := New(root, binary)
	if err := s.RecoverOrphan(t.Context()); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatal(err)
	}
	_ = cmd.Wait()
	for _, path := range []string{filepath.Join(root, "state", "frpc.pid"), configPath, secretPath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("runtime artifact should be removed: %s (err=%v)", path, err)
		}
	}
}

func TestEnqueueNeverRunsMutationsConcurrently(t *testing.T) {
	supervisor := New(t.TempDir(), "")
	var active, maximum int32
	var wait sync.WaitGroup
	for i := 0; i < 64; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			done := make(chan struct{})
			supervisor.Enqueue(func() {
				current := atomic.AddInt32(&active, 1)
				for {
					old := atomic.LoadInt32(&maximum)
					if current <= old || atomic.CompareAndSwapInt32(&maximum, old, current) {
						break
					}
				}
				time.Sleep(time.Millisecond)
				atomic.AddInt32(&active, -1)
				close(done)
			})
			<-done
		}()
	}
	wait.Wait()
	if maximum != 1 {
		t.Fatalf("supervisor executed %d concurrent mutations", maximum)
	}
}
