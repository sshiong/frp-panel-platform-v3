package httpapi

import (
	"testing"
	"time"
)

func TestRequestRateLimiter(t *testing.T) {
	limiter := newRequestRateLimiter(2, time.Minute)
	now := time.Now()
	if ok, _ := limiter.allow("ip", now); !ok {
		t.Fatal("first request should be allowed")
	}
	if ok, _ := limiter.allow("ip", now.Add(time.Second)); !ok {
		t.Fatal("second request should be allowed")
	}
	if ok, retry := limiter.allow("ip", now.Add(2*time.Second)); ok || retry <= 0 {
		t.Fatalf("third request should be limited, retry=%s", retry)
	}
	limiter.reset("ip")
	if ok, _ := limiter.allow("ip", now.Add(3*time.Second)); !ok {
		t.Fatal("reset should allow a new request")
	}
}
