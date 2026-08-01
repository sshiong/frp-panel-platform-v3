package httpapi

import (
	"sync"
	"time"
)

// requestRateLimiter is deliberately small and in-memory. It protects the
// local HTTP boundary from accidental retry storms and credential spraying;
// durable authorization still lives in the Server session/database layer.
type requestRateLimiter struct {
	mu      sync.Mutex
	entries map[string]rateBucket
	limit   int
	window  time.Duration
}

type rateBucket struct {
	started time.Time
	count   int
}

func newRequestRateLimiter(limit int, window time.Duration) *requestRateLimiter {
	return &requestRateLimiter{entries: make(map[string]rateBucket), limit: limit, window: window}
}

func (l *requestRateLimiter) allow(key string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.entries) > 4096 {
		l.entries = make(map[string]rateBucket)
	}
	bucket := l.entries[key]
	if bucket.started.IsZero() || now.Sub(bucket.started) >= l.window {
		bucket = rateBucket{started: now}
	}
	if bucket.count >= l.limit {
		remaining := l.window - now.Sub(bucket.started)
		if remaining < time.Second {
			remaining = time.Second
		}
		return false, remaining
	}
	bucket.count++
	l.entries[key] = bucket
	return true, 0
}

func (l *requestRateLimiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}
