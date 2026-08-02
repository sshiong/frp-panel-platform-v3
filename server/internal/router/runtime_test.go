package router

import (
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRuntimeValidationAndHelperEdges(t *testing.T) {
	if _, err := NewRuntime(nil, "://bad", "http://127.0.0.1:8080"); err == nil {
		t.Fatal("invalid control target was accepted")
	}
	if _, err := NewRuntime(nil, "http://127.0.0.1:7400", "not-a-url"); err == nil {
		t.Fatal("invalid business target was accepted")
	}
	runtime, err := NewRuntime([]byte("runtime-key"), "http://127.0.0.1:7400", "http://127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.LoadFile(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("missing snapshot file was accepted")
	}
	badPath := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(badPath, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runtime.LoadFile(badPath); err == nil {
		t.Fatal("malformed snapshot file was accepted")
	}
	if err := runtime.Load(Snapshot{SchemaVersion: "v1", Version: 0}); err == nil {
		t.Fatal("zero-version snapshot was accepted")
	}
	snapshot, err := Build(1, nil, nil, []byte("runtime-key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Load(snapshot); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Load(snapshot); err == nil {
		t.Fatal("stale snapshot was accepted")
	}
	if _, err := TLSConfig(nil).GetCertificate(&tls.ClientHelloInfo{ServerName: "unknown.example.com"}); err == nil {
		t.Fatal("empty TLS certificate map accepted unknown SNI")
	}
	for _, value := range []string{"Example.COM.:8080", "[::1]:443", "plain.example.com"} {
		if normalizeHost(value) == "" {
			t.Fatalf("host normalization returned empty value for %q", value)
		}
	}
	if host, port, err := netSplitHostPort("[::1]:443"); err != nil || host != "::1" || port != "443" {
		t.Fatalf("bracketed host parse: %q %q %v", host, port, err)
	}
	if _, _, err := netSplitHostPort("[::1]"); err == nil {
		t.Fatal("bracketed host without port was accepted")
	}
	if requestProto(httptest.NewRequest(http.MethodGet, "http://example.com", nil)) != "http" {
		t.Fatal("plain request protocol mismatch")
	}
	secureRequest := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
	secureRequest.TLS = &tls.ConnectionState{}
	if requestProto(secureRequest) != "https" {
		t.Fatal("TLS request protocol mismatch")
	}
}

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

func TestRuntimeSnapshotReloadDoesNotInterruptInFlightProxy(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	upstream := newLoopbackTestServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		flusher, _ := w.(http.Flusher)
		_, _ = w.Write([]byte("start"))
		if flusher != nil {
			flusher.Flush()
		}
		close(started)
		<-release
		_, _ = w.Write([]byte("-done"))
	}))
	defer upstream.Close()

	key := []byte("reload-key")
	runtime, err := NewRuntime(key, "http://127.0.0.1:7400", upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	first, err := Build(1, nil, []Route{{Hostname: "app.example.com", Status: "active"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Load(first); err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "http://app.example.com/long", nil)
	request.Host = "app.example.com"
	response := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		runtime.ServeHTTP(response, request)
		close(done)
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("proxy did not establish the in-flight request")
	}

	second, err := Build(2, nil, []Route{{Hostname: "app.example.com", Status: "active"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Load(second); err != nil {
		t.Fatal(err)
	}
	close(release)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("in-flight proxy did not finish after snapshot reload")
	}
	if runtime.CurrentVersion() != 2 {
		t.Fatalf("snapshot version=%d, want 2", runtime.CurrentVersion())
	}
	if !strings.Contains(response.Body.String(), "start-done") {
		t.Fatalf("in-flight response was interrupted: %q", response.Body.String())
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
