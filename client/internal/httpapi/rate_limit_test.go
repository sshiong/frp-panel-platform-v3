package httpapi

import (
	"testing"
	"time"
)

func TestRequestRateLimiter(t *testing.T) {
	limiter := newRequestRateLimiter(1, time.Minute)
	now := time.Now()
	if ok, _ := limiter.allow("ip", now); !ok {
		t.Fatal("first request should be allowed")
	}
	if ok, retry := limiter.allow("ip", now.Add(time.Second)); ok || retry <= 0 {
		t.Fatalf("second request should be limited, retry=%s", retry)
	}
	if ok, _ := limiter.allow("ip", now.Add(time.Minute)); !ok {
		t.Fatal("window expiry should allow a new request")
	}
}
