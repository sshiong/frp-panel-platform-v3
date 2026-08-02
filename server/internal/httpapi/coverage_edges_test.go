package httpapi

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ricardo/frp-panel-platform/server/internal/service"
)

func TestHTTPBoundaryMiddlewareAndJSONEdges(t *testing.T) {
	terminal := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	api := &API{
		Origin: map[string]bool{"https://allowed.example": true},
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	request.Header.Set("X-Request-ID", strings.Repeat("x", 81))
	recorder := httptest.NewRecorder()
	api.requestID(terminal).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("X-Request-ID") == "" || len(recorder.Header().Get("X-Request-ID")) > 80 {
		t.Fatalf("request ID middleware: status=%d id=%q", recorder.Code, recorder.Header().Get("X-Request-ID"))
	}

	options := httptest.NewRequest(http.MethodOptions, "http://example.test/", nil)
	options.Header.Set("Origin", "https://allowed.example")
	recorder = httptest.NewRecorder()
	api.cors(terminal).ServeHTTP(recorder, options)
	if recorder.Code != http.StatusNoContent || recorder.Header().Get("Access-Control-Allow-Origin") != "https://allowed.example" {
		t.Fatalf("allowed CORS preflight: status=%d headers=%v", recorder.Code, recorder.Header())
	}
	unknownOrigin := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	unknownOrigin.Header.Set("Origin", "https://unknown.example")
	recorder = httptest.NewRecorder()
	api.cors(terminal).ServeHTTP(recorder, unknownOrigin)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("unknown origin handling: status=%d headers=%v", recorder.Code, recorder.Header())
	}

	nonLoopback := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	nonLoopback.RemoteAddr = "203.0.113.5:1234"
	recorder = httptest.NewRecorder()
	api.loopbackOnly(terminal).ServeHTTP(recorder, nonLoopback)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("non-loopback internal request status=%d", recorder.Code)
	}
	loopback := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	loopback.RemoteAddr = "127.0.0.1:1234"
	recorder = httptest.NewRecorder()
	api.loopbackOnly(terminal).ServeHTTP(recorder, loopback)
	if recorder.Code != http.StatusOK {
		t.Fatalf("loopback internal request status=%d", recorder.Code)
	}

	api.apiLimit = newRequestRateLimiter(0, time.Minute)
	recorder = httptest.NewRecorder()
	api.rateLimit(terminal).ServeHTTP(recorder, loopback)
	if recorder.Code != http.StatusTooManyRequests || recorder.Header().Get("Retry-After") == "" {
		t.Fatalf("rate limit response: status=%d headers=%v", recorder.Code, recorder.Header())
	}
	api.apiLimit = nil
	recorder = httptest.NewRecorder()
	api.rateLimit(terminal).ServeHTTP(recorder, loopback)
	if recorder.Code != http.StatusOK {
		t.Fatalf("nil rate limiter response: %d", recorder.Code)
	}

	api.concurrency = make(chan struct{}, 1)
	api.concurrency <- struct{}{}
	recorder = httptest.NewRecorder()
	api.concurrencyLimit(terminal).ServeHTTP(recorder, loopback)
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("concurrency limit response: %d", recorder.Code)
	}
	<-api.concurrency
	api.concurrency = nil
	recorder = httptest.NewRecorder()
	api.concurrencyLimit(terminal).ServeHTTP(recorder, loopback)
	if recorder.Code != http.StatusOK {
		t.Fatalf("nil concurrency limiter response: %d", recorder.Code)
	}

	adminRequest := httptest.NewRequest(http.MethodGet, "http://example.test/admin", nil)
	adminRequest = adminRequest.WithContext(context.WithValue(adminRequest.Context(), authContextKey, service.AuthContext{Role: "admin"}))
	recorder = httptest.NewRecorder()
	api.requireAdmin(terminal).ServeHTTP(recorder, adminRequest)
	if recorder.Code != http.StatusOK {
		t.Fatalf("admin authorization response: %d", recorder.Code)
	}
	userRequest := httptest.NewRequest(http.MethodGet, "http://example.test/admin", nil)
	userRequest = userRequest.WithContext(context.WithValue(userRequest.Context(), authContextKey, service.AuthContext{Role: "user"}))
	recorder = httptest.NewRecorder()
	api.requireAdmin(terminal).ServeHTTP(recorder, userRequest)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("user admin authorization response: %d", recorder.Code)
	}

	if handler := RouteManifestHandler(); handler == nil {
		t.Fatal("route manifest handler is nil")
	}
	if page, size := pageParams(httptest.NewRequest(http.MethodGet, "http://example.test/?page=0&page_size=999", nil)); page != 1 || size != 200 {
		t.Fatalf("page bounds: %d/%d", page, size)
	}
	if remoteIP(httptest.NewRequest(http.MethodGet, "http://example.test/", nil)) == "" {
		t.Fatal("remote IP fallback is empty")
	}

	var decoded struct {
		Name string `json:"name"`
	}
	valid := httptest.NewRequest(http.MethodPost, "http://example.test/", strings.NewReader(`{"name":"ok"}`))
	recorder = httptest.NewRecorder()
	if !decodeJSON(recorder, valid, &decoded) || decoded.Name != "ok" {
		t.Fatalf("valid JSON decode: %#v status=%d", decoded, recorder.Code)
	}
	for _, body := range []string{"{", `{"unknown":true}`, `{"name":"ok"}{"name":"extra"}`} {
		bad := httptest.NewRequest(http.MethodPost, "http://example.test/", strings.NewReader(body))
		recorder = httptest.NewRecorder()
		if decodeJSON(recorder, bad, &decoded) || recorder.Code != http.StatusBadRequest {
			t.Fatalf("invalid JSON accepted: body=%q status=%d", body, recorder.Code)
		}
	}
	nilBody := httptest.NewRequest(http.MethodPost, "http://example.test/", nil)
	nilBody.Body = nil
	recorder = httptest.NewRecorder()
	if decodeJSON(recorder, nilBody, &decoded) || recorder.Code != http.StatusBadRequest {
		t.Fatalf("nil JSON body accepted: status=%d", recorder.Code)
	}

	problemRequest := httptest.NewRequest(http.MethodGet, "http://example.test/problem", nil)
	problemRequest = problemRequest.WithContext(context.WithValue(problemRequest.Context(), requestIDKey, "problem-request"))
	recorder = httptest.NewRecorder()
	problem(recorder, problemRequest, http.StatusInternalServerError, "INTERNAL_TEST", "sensitive detail", nil)
	if recorder.Code != http.StatusInternalServerError || !strings.Contains(recorder.Body.String(), "服务暂时不可用") {
		t.Fatalf("problem response: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	problem(nil, problemRequest, http.StatusBadRequest, "NO_WRITER", "", nil)
}

func TestMappingProblemMapsQuotaFailure(t *testing.T) {
	api := &API{}
	request := httptest.NewRequest(http.MethodPost, "http://example.test/api/v1/mappings", nil)
	recorder := httptest.NewRecorder()
	api.mappingProblem(recorder, request, errors.New("pending mapping quota exceeded"))
	if recorder.Code != http.StatusTooManyRequests || !strings.Contains(recorder.Body.String(), "QUOTA_EXCEEDED") {
		t.Fatalf("quota problem response: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
