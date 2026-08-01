package router

import (
	"crypto/sha256"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestRuntimeRejectsBadSnapshotAndRoutesByHost(t *testing.T) {
	control := newLoopbackTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("control:" + r.URL.Path)) }))
	defer control.Close()
	business := newLoopbackTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("business:" + r.URL.Path)) }))
	defer business.Close()
	controlURL, _ := url.Parse(control.URL)
	businessURL, _ := url.Parse(business.URL)
	key := sha256.Sum256([]byte("router"))
	runtime, err := NewRuntime(key[:], controlURL.String(), businessURL.String())
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := Build(1, []Route{{Hostname: "panel.example.com", Target: controlURL.String(), Status: "active"}}, []Route{{Hostname: "app.example.com", Target: businessURL.String(), Status: "active"}}, key[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Load(snapshot); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://panel.example.com/admin", nil)
	request.Host = "panel.example.com"
	response := httptest.NewRecorder()
	runtime.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "control:/admin" {
		t.Fatalf("control response: %d %q", response.Code, response.Body.String())
	}
	request = httptest.NewRequest(http.MethodGet, "http://app.example.com/stream", nil)
	request.Host = "app.example.com"
	response = httptest.NewRecorder()
	runtime.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "business:/stream" {
		t.Fatalf("business response: %d %q", response.Code, response.Body.String())
	}
	bad := snapshot
	bad.HMAC = fmt.Sprintf("%x", []byte("bad"))
	if err := runtime.Load(bad); err == nil {
		t.Fatal("bad HMAC must be rejected")
	}
	request = httptest.NewRequest(http.MethodGet, "http://unknown.example.com/", nil)
	request.Host = "unknown.example.com"
	response = httptest.NewRecorder()
	runtime.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("unknown host status: %d", response.Code)
	}
}

func TestRuntimeRedirectsConfiguredHTTPHost(t *testing.T) {
	key := []byte("test-router-key")
	runtime, err := NewRuntime(key, "http://127.0.0.1:7400", "http://127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := Build(1, nil, []Route{{Hostname: "app.example.com", HTTPRedirect: true, Status: "active"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Load(snapshot); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/health?ready=1", nil)
	req.Host = "app.example.com"
	runtime.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusPermanentRedirect || recorder.Header().Get("Location") != "https://app.example.com/health?ready=1" {
		t.Fatalf("redirect response: code=%d location=%q", recorder.Code, recorder.Header().Get("Location"))
	}
}

func TestRuntimeOfflineRouteReturns502(t *testing.T) {
	control := newLoopbackTestServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer control.Close()
	business := newLoopbackTestServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer business.Close()
	runtime, err := NewRuntime(nil, control.URL, business.URL)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, _ := Build(1, nil, []Route{{Hostname: "app.example.com", Status: "offline"}}, nil)
	if err := runtime.Load(snapshot); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
	request.Host = "app.example.com"
	response := httptest.NewRecorder()
	runtime.ServeHTTP(response, request)
	if response.Code != http.StatusBadGateway {
		t.Fatalf("offline route status: %d", response.Code)
	}
}

func newLoopbackTestServer(handler http.Handler) *httptest.Server {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.Listener = listener
	server.Start()
	return server
}
