package id

import (
	"github.com/google/uuid"
	"testing"
)

func TestNewReturnsUUIDv7(t *testing.T) {
	parsed, err := uuid.Parse(New())
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Version() != 7 {
		t.Fatalf("generated ID version=%d; want 7", parsed.Version())
	}
}
