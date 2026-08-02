package router

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestSnapshotHMAC(t *testing.T) {
	snapshot, err := Build(1, []Route{{Hostname: "panel.example.com", Target: "control", Status: "active"}}, nil, []byte("router-key"))
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(snapshot, []byte("router-key")) {
		t.Fatal("snapshot should verify")
	}
	if Verify(snapshot, []byte("wrong-key")) {
		t.Fatal("wrong key must fail")
	}
	badHash := snapshot
	badHash.Hash = "not-the-declared-hash"
	if Verify(badHash, []byte("router-key")) {
		t.Fatal("tampered snapshot hash must fail")
	}
	badHMAC := snapshot
	badHMAC.HMAC = "not-the-declared-hmac"
	if Verify(badHMAC, []byte("router-key")) {
		t.Fatal("tampered snapshot HMAC must fail")
	}
}

func TestAtomicWriteRejectsUnsupportedSchema(t *testing.T) {
	root := t.TempDir()
	if err := AtomicWrite(filepath.Join(root, "snapshot.json"), Snapshot{SchemaVersion: "v0"}); err == nil {
		t.Fatal("unsupported Router snapshot schema was accepted")
	}
	key := []byte("snapshot-directory-target")
	snapshot, err := Build(1, nil, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	directoryTarget := filepath.Join(root, "target-directory")
	if err := os.MkdirAll(directoryTarget, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWrite(directoryTarget, snapshot); err == nil {
		t.Fatal("atomic write over a directory was accepted")
	}
}

func TestAtomicWriteFailureLeavesLastGoodSnapshotUntouched(t *testing.T) {
	root := t.TempDir()
	lastGoodPath := filepath.Join(root, "last-good.json")
	key := []byte("atomic-write-key")
	lastGood, err := Build(1, nil, []Route{{Hostname: "one.example.com", Status: "active"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := AtomicWrite(lastGoodPath, lastGood); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(lastGoodPath)
	if err != nil {
		t.Fatal(err)
	}

	// ENOTDIR is a deterministic stand-in for a failed destination such as a
	// full/unavailable filesystem. It must not replace the already durable
	// last-good snapshot.
	blockedParent := filepath.Join(root, "blocked-parent")
	if err := os.WriteFile(blockedParent, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	next, err := Build(2, nil, []Route{{Hostname: "two.example.com", Status: "active"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := AtomicWrite(filepath.Join(blockedParent, "last-good.json"), next); err == nil {
		t.Fatal("atomic write through a non-directory parent should fail")
	}
	after, err := os.ReadFile(lastGoodPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("failed atomic write changed the last-good snapshot")
	}
}
