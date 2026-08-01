package auth

import "testing"

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
