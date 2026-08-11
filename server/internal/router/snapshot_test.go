package router

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"syscall"
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

func TestAtomicWriteDiskFullLeavesLastGoodSnapshotUntouched(t *testing.T) {
	root := os.Getenv("FRP_DISK_FULL_DIR")
	if root == "" {
		t.Skip("set FRP_DISK_FULL_DIR to a disposable full filesystem")
	}
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() {
		t.Fatalf("FRP_DISK_FULL_DIR is not a directory: %s", root)
	}

	lastGoodPath := filepath.Join(root, "last-good.json")
	snapshot, err := Build(1, nil, []Route{{Hostname: "stable.example.com", Status: "active"}}, []byte("disk-full-key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := AtomicWrite(lastGoodPath, snapshot); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(lastGoodPath)
	if err != nil {
		t.Fatal(err)
	}

	fillPath := filepath.Join(root, "fill.bin")
	fill, err := os.OpenFile(fillPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = fill.Close()
		_ = os.Remove(fillPath)
	})
	chunk := bytes.Repeat([]byte("f"), 1024*1024)
	for {
		if _, err := fill.Write(chunk); err != nil {
			if !errors.Is(err, syscall.ENOSPC) {
				t.Fatalf("filling disposable filesystem failed with %v, want ENOSPC", err)
			}
			break
		}
	}
	_ = fill.Close()

	next, err := Build(2, nil, []Route{{Hostname: "new.example.com", Status: "active"}}, []byte("disk-full-key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := AtomicWrite(filepath.Join(root, "next.json"), next); err == nil {
		t.Fatal("atomic write unexpectedly succeeded on a full filesystem")
	}
	after, err := os.ReadFile(lastGoodPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("disk-full atomic write changed the last-good snapshot")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".json" && entry.Name() != "last-good.json" {
			t.Fatalf("failed disk-full write left a candidate snapshot: %s", entry.Name())
		}
	}
}
