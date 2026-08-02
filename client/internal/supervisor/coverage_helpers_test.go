package supervisor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestSupervisorCoverageHelpersAndRuntimeArtifacts(t *testing.T) {
	root := t.TempDir()
	s := New(root, "")

	if err := s.writeRuntimeSecrets(Snapshot{Payload: map[string]interface{}{}}); err == nil {
		t.Fatal("incomplete runtime secrets were accepted")
	}
	snapshot := Snapshot{ConfigVersion: 4, SessionGeneration: 2, Payload: map[string]interface{}{
		"frps_public_host":   "frp.example.com",
		"frps_public_port":   7000,
		"frp_username":       "coverage-user",
		"frp_secret":         "user-secret",
		"runtime_credential": "runtime-secret",
		"mappings": []interface{}{map[string]interface{}{
			"mapping_id":     "mapping-1",
			"proxy_type":     "http",
			"local_ip":       "127.0.0.1",
			"local_port":     8080,
			"revision":       int64(2),
			"custom_domains": []interface{}{"app.example.com", "www.example.com"},
		}},
	}}
	if err := s.writeRuntimeSecrets(snapshot); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.lastSnapshot = &Snapshot{Payload: map[string]interface{}{
		"frp_secret":            "secret-in-memory",
		"frp_user_secret":       "secret-in-memory",
		"runtime_credential":    "runtime-in-memory",
		"frps_transport_secret": "transport-in-memory",
	}}
	s.mu.Unlock()
	for _, name := range []string{"transport-token", "user-frp-secret", "runtime-token"} {
		if _, err := os.Stat(filepath.Join(root, "runtime", "secrets", name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.verify(context.Background(), "config.toml"); err != nil {
		t.Fatal(err)
	}
	if err := s.verify(context.Background(), ""); err == nil {
		t.Fatal("empty config path was accepted")
	}
	if rendered := renderTOMLForVersion(snapshot, root, "0.63.0"); !strings.Contains(rendered, `auth.token = "user-secret"`) || !strings.Contains(rendered, `customDomains`) {
		t.Fatalf("legacy TOML branch or custom domains missing:\n%s", rendered)
	}
	if rendered := renderTOMLForVersion(snapshot, root, "0.68.0"); !strings.Contains(rendered, `auth.tokenSource.type = "file"`) {
		t.Fatalf("modern TOML branch missing:\n%s", rendered)
	}

	if err := s.writePID(12345); err != nil {
		t.Fatal(err)
	}
	if err := s.removePIDIf(12346); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.pidPath()); err != nil {
		t.Fatal(err)
	}
	if err := s.removePIDIf(12345); err != nil {
		t.Fatal(err)
	}
	if err := s.clearRecoveredRuntime(); err != nil {
		t.Fatal(err)
	}
	s.mu.RLock()
	if s.lastSnapshot != nil {
		s.mu.RUnlock()
		t.Fatal("runtime-only snapshot remained in Supervisor memory")
	}
	s.mu.RUnlock()
	if _, err := os.Stat(filepath.Join(root, "runtime", "secrets")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("runtime secrets were not cleared: %v", err)
	}

	if !processCommandGone(" <defunct> ") || processCommandGone("/usr/bin/frpc -c config") {
		t.Fatal("process command identity helper mismatch")
	}
	if !frpcVersionAtLeast("0.68.0", "0.68.0") || frpcVersionAtLeast("0.67.0", "0.68.0") || frpcVersionAtLeast("invalid", "0.68.0") || frpcVersionAtLeast("0.68", "invalid") {
		t.Fatal("FRPC version comparison mismatch")
	}
	if payloadInt(map[string]interface{}{"n": int(3)}, "n", 0) != 3 || payloadInt(map[string]interface{}{"n": int64(4)}, "n", 0) != 4 || payloadInt(map[string]interface{}{"n": "bad"}, "n", 9) != 9 {
		t.Fatal("payload integer conversion mismatch")
	}
	if got := sanitize(strings.Repeat("x", 300)); len(got) != 240 || !strings.Contains(sanitize("Bearer token"), "[redacted]") {
		t.Fatal("runtime error sanitization mismatch")
	}

	if err := os.MkdirAll(filepath.Join(root, "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.pidPath(), []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.RecoverOrphan(context.Background()); err == nil || !strings.Contains(err.Error(), "current client process") {
		t.Fatalf("current process PID marker was not rejected: %v", err)
	}
	if err := os.WriteFile(s.pidPath(), []byte("not-a-pid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.RecoverOrphan(context.Background()); err == nil || !strings.Contains(err.Error(), "invalid frpc pid") {
		t.Fatalf("invalid PID marker was not rejected: %v", err)
	}
	if err := os.Remove(s.pidPath()); err != nil {
		t.Fatal(err)
	}
	if err := s.RecoverOrphan(context.Background()); err != nil {
		t.Fatal(err)
	}
}
