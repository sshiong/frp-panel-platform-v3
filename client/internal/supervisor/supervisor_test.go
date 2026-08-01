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
	"path/filepath"
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

func TestRealBinaryVerifyRestartAndStop(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "config"), 0o700); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(root, "fake-frpc")
	script := []byte("#!/bin/sh\nif [ \"$1\" = \"verify\" ]; then exit 0; fi\ntrap 'exit 0' INT TERM\nwhile true; do sleep 1; done\n")
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
