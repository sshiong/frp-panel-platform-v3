package clock

import (
	"errors"
	"fmt"
	"net/http"
	"time"
)

const DefaultTolerance = 5 * time.Minute

var ErrSkew = errors.New("clock skew exceeds tolerance")

// Check compares a local clock reading with a trusted external reference.
// Session/database timestamps alone cannot detect an equally skewed host, so
// provider responses with an HTTP Date header are the production signal.
func Check(reference, local time.Time, tolerance time.Duration) error {
	if tolerance <= 0 {
		tolerance = DefaultTolerance
	}
	delta := local.Sub(reference)
	if delta < 0 {
		delta = -delta
	}
	if delta > tolerance {
		return fmt.Errorf("%w: local/reference delta=%s tolerance=%s", ErrSkew, delta, tolerance)
	}
	return nil
}

func ValidateResponse(response *http.Response, tolerance time.Duration) error {
	if response == nil {
		return nil
	}
	value := response.Header.Get("Date")
	if value == "" {
		return nil
	}
	reference, err := http.ParseTime(value)
	if err != nil {
		return fmt.Errorf("invalid provider Date header: %w", err)
	}
	return Check(reference, time.Now().UTC(), tolerance)
}

// RoundTripper makes ACME's direct HTTP traffic use the same clock-skew
// detection as the Cloudflare adapter without changing the mature ACME client.
type RoundTripper struct {
	Base      http.RoundTripper
	Tolerance time.Duration
}

func (t RoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	response, err := base.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	if err := ValidateResponse(response, t.Tolerance); err != nil {
		_ = response.Body.Close()
		return nil, err
	}
	return response, nil
}

func NewRoundTripper(base http.RoundTripper, tolerance time.Duration) http.RoundTripper {
	return RoundTripper{Base: base, Tolerance: tolerance}
}
