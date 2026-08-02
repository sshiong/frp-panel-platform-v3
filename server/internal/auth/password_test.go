package auth

import (
	"errors"
	"testing"
)

func TestPasswordHashRoundTrip(t *testing.T) {
	hash, err := HashPassword("correct-horse-battery")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(hash, "correct-horse-battery") {
		t.Fatal("password should verify")
	}
	if VerifyPassword(hash, "wrong-password") {
		t.Fatal("wrong password must fail")
	}
}

func TestPasswordValidationRejectsMalformedCredentials(t *testing.T) {
	if _, err := HashPassword("short"); err == nil {
		t.Fatal("short password was accepted")
	}
	for _, encoded := range []string{"", "plain", "$argon2id$v=18$m=1,t=1,p=1$bad$bad", "$argon2id$v=19$bad", "$argon2id$v=19$m=1,t=1,p=1$%%%$bad", "$argon2id$v=19$m=1,t=1,p=1$YWJj$"} {
		if VerifyPassword(encoded, "some-password-2026") {
			t.Fatalf("malformed encoded password was accepted: %q", encoded)
		}
	}
}

type failingPasswordReader struct{}

func (failingPasswordReader) Read([]byte) (int, error) { return 0, errors.New("entropy unavailable") }

func TestHashPasswordPropagatesEntropyFailure(t *testing.T) {
	original := passwordRandomReader
	passwordRandomReader = failingPasswordReader{}
	t.Cleanup(func() { passwordRandomReader = original })
	if _, err := HashPassword("password-with-enough-length"); err == nil {
		t.Fatal("entropy failure was swallowed")
	}
}
