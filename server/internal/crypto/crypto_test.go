package crypto

import "testing"

func TestEncryptUsesAAD(t *testing.T) {
	manager := &Manager{MasterKey: []byte("01234567890123456789012345678901")}
	ciphertext, nonce, err := manager.Encrypt([]byte("token-value"), "user:u:token:v1")
	if err != nil {
		t.Fatal(err)
	}
	plain, err := manager.Decrypt(ciphertext, nonce, "user:u:token:v1")
	if err != nil || string(plain) != "token-value" {
		t.Fatalf("decrypt mismatch: %q %v", plain, err)
	}
	if _, err := manager.Decrypt(ciphertext, nonce, "user:other:token:v1"); err == nil {
		t.Fatal("AAD mismatch must fail")
	}
}
