package id

import "github.com/google/uuid"

// New returns a time-ordered UUID for request, WebSocket and idempotency
// identifiers. It keeps the fallback local and opaque if entropy fails.
func New() string {
	value, err := uuid.NewV7()
	if err != nil {
		return uuid.NewString()
	}
	return value.String()
}
