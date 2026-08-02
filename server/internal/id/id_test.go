package id

import (
	"github.com/google/uuid"
	"testing"
)

func TestNewReturnsTimeOrderedUUIDv7(t *testing.T) {
	first := New()
	second := New()
	for _, value := range []string{first, second} {
		parsed, err := uuid.Parse(value)
		if err != nil {
			t.Fatalf("generated ID is not UUID: %q: %v", value, err)
		}
		if parsed.Version() != 7 {
			t.Fatalf("generated ID version=%d; want 7", parsed.Version())
		}
	}
	if first >= second {
		t.Fatalf("UUIDv7 IDs are not ordered: %s >= %s", first, second)
	}
}
