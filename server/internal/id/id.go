package id

import "github.com/google/uuid"

// New returns a time-ordered UUID for database and operation identifiers.
// UUIDv7 preserves the sortable-random property required by the platform;
// the v4 fallback is only reachable if the dependency's entropy source fails.
func New() string {
	value, err := uuid.NewV7()
	if err != nil {
		return uuid.NewString()
	}
	return value.String()
}
