package httpapi

import "testing"

func TestHostAllowed(t *testing.T) {
	for _, test := range []struct {
		name     string
		request  string
		allowed  string
		expected bool
	}{
		{name: "default loopback with port", request: "127.0.0.1:7410", allowed: "127.0.0.1,localhost,[::1]", expected: true},
		{name: "localhost", request: "localhost:7410", allowed: "127.0.0.1,localhost,[::1]", expected: true},
		{name: "ipv6", request: "[::1]:7410", allowed: "127.0.0.1,localhost,[::1]", expected: true},
		{name: "wrong host", request: "evil.example:7410", allowed: "127.0.0.1,localhost,[::1]", expected: false},
		{name: "wrong port when pinned", request: "127.0.0.1:7411", allowed: "127.0.0.1:7410", expected: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := hostAllowed(test.request, test.allowed); got != test.expected {
				t.Fatalf("hostAllowed(%q, %q) = %v, want %v", test.request, test.allowed, got, test.expected)
			}
		})
	}
}

func TestCIDRAllowed(t *testing.T) {
	if !cidrAllowed("127.0.0.1:7410", []string{"127.0.0.0/8"}) {
		t.Fatal("loopback should be allowed")
	}
	if !cidrAllowed("[::1]:7410", []string{"::1/128"}) {
		t.Fatal("IPv6 loopback should be allowed")
	}
	if cidrAllowed("192.0.2.10:7410", []string{"198.51.100.0/24"}) {
		t.Fatal("address outside the allowlist should be rejected")
	}
}
