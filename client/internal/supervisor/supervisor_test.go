package supervisor

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
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
