package router

import "testing"

func FuzzSnapshotRoundTrip(f *testing.F) {
	for _, seed := range []string{"example.com", "用户.example", "api.example.com"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, host string) {
		snapshot, err := Build(1, []Route{{Hostname: host, Target: "http://127.0.0.1:7400", Status: "active"}}, nil, []byte("test-router-key"))
		if err != nil {
			t.Fatal(err)
		}
		if !Verify(snapshot, []byte("test-router-key")) {
			t.Fatal("fresh snapshot did not verify")
		}
		snapshot.Hash = "bad"
		if Verify(snapshot, []byte("test-router-key")) {
			t.Fatal("tampered snapshot verified")
		}
	})
}
