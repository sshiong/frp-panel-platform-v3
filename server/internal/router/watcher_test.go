package router

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWatcherLoadsAtomicSnapshotAndRetainsLastGood(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "last-good.json")
	key := []byte("watcher-key")
	runtime, err := NewRuntime(key, "http://127.0.0.1:7400", "http://127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := Build(1, nil, []Route{{Hostname: "one.example.com", Status: "active"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := AtomicWrite(path, snapshot); err != nil {
		t.Fatal(err)
	}
	watcher := &Watcher{Runtime: runtime, SnapshotPath: path}
	fingerprint := watcher.reloadIfChanged(fileFingerprint{})
	if runtime.CurrentVersion() != 1 || !fingerprint.present {
		t.Fatalf("snapshot was not loaded: version=%d fingerprint=%#v", runtime.CurrentVersion(), fingerprint)
	}
	if err := os.WriteFile(path, []byte(`{"schema_version":"v1","version":2,"hmac":"bad"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, fingerprint.modified.Add(1), fingerprint.modified.Add(1)); err != nil {
		t.Fatal(err)
	}
	var observed error
	watcher.OnError = func(err error) { observed = err }
	watcher.reloadIfChanged(fingerprint)
	if runtime.CurrentVersion() != 1 || observed == nil {
		t.Fatalf("bad snapshot displaced last-good: version=%d err=%v", runtime.CurrentVersion(), observed)
	}
}
