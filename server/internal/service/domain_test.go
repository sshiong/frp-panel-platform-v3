package service

import "testing"

func TestNormalizeDomain(t *testing.T) {
	got, err := normalizeDomain("  APP.Example.COM. ")
	if err != nil || got != "app.example.com" {
		t.Fatalf("got %q, err %v", got, err)
	}
	got, err = normalizeDomain("例子.测试")
	if err != nil || got == "" {
		t.Fatalf("IDNA domain should normalize: %q %v", got, err)
	}
	if _, err := normalizeDomain("*.example.com"); err == nil {
		t.Fatal("wildcard must be rejected")
	}
}
