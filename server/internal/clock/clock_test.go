package clock

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestCheckDetectsClockSkew(t *testing.T) {
	now := time.Date(2026, time.August, 2, 0, 0, 0, 0, time.UTC)
	if err := Check(now.Add(-30*time.Second), now, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := Check(now.Add(-2*time.Minute), now, time.Minute); !errors.Is(err, ErrSkew) {
		t.Fatalf("expected clock skew error, got %v", err)
	}
}

func TestValidateResponseUsesHTTPDate(t *testing.T) {
	response := &http.Response{Header: make(http.Header)}
	response.Header.Set("Date", time.Now().UTC().Add(-10*time.Minute).Format(http.TimeFormat))
	if err := ValidateResponse(response, time.Minute); !errors.Is(err, ErrSkew) {
		t.Fatalf("expected provider clock skew error, got %v", err)
	}
}

func TestClockDefaultsAndHTTPDateValidation(t *testing.T) {
	now := time.Now().UTC()
	if err := Check(now, now, 0); err != nil {
		t.Fatal(err)
	}
	if err := ValidateResponse(nil, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := ValidateResponse(&http.Response{Header: make(http.Header)}, time.Minute); err != nil {
		t.Fatal(err)
	}
	response := &http.Response{Header: make(http.Header)}
	response.Header.Set("Date", "not-a-date")
	if err := ValidateResponse(response, time.Minute); err == nil || !strings.Contains(err.Error(), "invalid provider Date header") {
		t.Fatalf("expected invalid Date error, got %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func TestRoundTripperValidatesAndClosesSkewedResponses(t *testing.T) {
	request, err := http.NewRequest(http.MethodGet, "https://provider.example.test", nil)
	if err != nil {
		t.Fatal(err)
	}
	valid := NewRoundTripper(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok"))}, nil
	}), time.Minute)
	response, err := valid.RoundTrip(request)
	if err != nil || response == nil {
		t.Fatalf("valid response rejected: %v", err)
	}
	_ = response.Body.Close()

	var closed bool
	skewed := RoundTripper{Base: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{Header: http.Header{"Date": []string{time.Now().UTC().Add(-10 * time.Minute).Format(http.TimeFormat)}}, Body: closeTracker{onClose: func() { closed = true }}}, nil
	}), Tolerance: time.Minute}
	if _, err := skewed.RoundTrip(request); !errors.Is(err, ErrSkew) {
		t.Fatalf("expected skew error, got %v", err)
	}
	if !closed {
		t.Fatal("skewed response body was not closed")
	}

	transportError := errors.New("transport failed")
	failed := RoundTripper{Base: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, transportError })}
	if _, err := failed.RoundTrip(request); !errors.Is(err, transportError) {
		t.Fatalf("transport error changed: %v", err)
	}
}

type closeTracker struct {
	onClose func()
}

func (c closeTracker) Read([]byte) (int, error) { return 0, io.EOF }

func (c closeTracker) Close() error {
	c.onClose()
	return nil
}
