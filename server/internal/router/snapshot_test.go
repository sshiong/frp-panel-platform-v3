package router

import "testing"

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
}
