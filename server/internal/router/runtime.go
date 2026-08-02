package router

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	maxRouterHeaderBytes = 64 << 10
	maxRouterBodyBytes   = 8 << 20
)

type Runtime struct {
	mu        sync.RWMutex
	key       []byte
	current   Snapshot
	control   *url.URL
	business  *url.URL
	transport http.RoundTripper
}

// CertificateStore is the Router-side, in-memory SNI certificate boundary.
// Control code can replace the complete set after it has decrypted and
// validated certificate material; the Router itself never reads SQLite or
// certificate files.
type CertificateStore struct {
	mu           sync.RWMutex
	certificates map[string]tls.Certificate
}

func NewCertificateStore() *CertificateStore {
	return &CertificateStore{certificates: make(map[string]tls.Certificate)}
}

func (s *CertificateStore) Replace(certificates map[string]tls.Certificate) {
	if s == nil {
		return
	}
	copySet := make(map[string]tls.Certificate, len(certificates))
	for hostname, certificate := range certificates {
		copySet[normalizeSNI(hostname)] = certificate
	}
	s.mu.Lock()
	s.certificates = copySet
	s.mu.Unlock()
}

func (s *CertificateStore) certificate(serverName string) (*tls.Certificate, error) {
	s.mu.RLock()
	certificate, ok := s.certificates[normalizeSNI(serverName)]
	s.mu.RUnlock()
	if !ok {
		return nil, errors.New("unknown SNI")
	}
	return &certificate, nil
}

func (s *CertificateStore) TLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return s.certificate(hello.ServerName)
	}}
}

func NewRuntime(key []byte, controlTarget, businessTarget string) (*Runtime, error) {
	control, err := url.Parse(controlTarget)
	if err != nil || control.Scheme == "" || control.Host == "" {
		return nil, errors.New("invalid router control target")
	}
	business, err := url.Parse(businessTarget)
	if err != nil || business.Scheme == "" || business.Host == "" {
		return nil, errors.New("invalid router business target")
	}
	return &Runtime{key: append([]byte(nil), key...), control: control, business: business, transport: routerTransport()}, nil
}

func (r *Runtime) LoadFile(path string) error {
	content, err := os.ReadFile(path) // #nosec G304 -- snapshot path is an operator-configured last-good file
	if err != nil {
		return err
	}
	var snapshot Snapshot
	if err := json.Unmarshal(content, &snapshot); err != nil {
		return fmt.Errorf("decode router snapshot: %w", err)
	}
	return r.Load(snapshot)
}

func (r *Runtime) Load(snapshot Snapshot) error {
	if snapshot.SchemaVersion != "v1" || snapshot.Version < 1 || !Verify(snapshot, r.key) {
		return errors.New("router snapshot integrity check failed")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.current.Version >= snapshot.Version {
		return errors.New("router snapshot version is not newer")
	}
	r.current = snapshot
	return nil
}

func (r *Runtime) CurrentVersion() int64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.current.Version
}

// ServeHTTP is a DB-free Router boundary. It selects by normalized Host and
// refuses unknown or offline routes. Proxy targets are fixed deployment
// targets; they are never supplied by a Domain Binding.
func (r *Runtime) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if requestHeaderBytes(req) > maxRouterHeaderBytes {
		http.Error(w, "request headers too large", http.StatusRequestHeaderFieldsTooLarge)
		return
	}
	r.mu.RLock()
	snapshot := r.current
	controlTarget, businessTarget := *r.control, *r.business
	r.mu.RUnlock()
	host := normalizeHost(req.Host)
	var selected *Route
	target := businessTarget
	for i := range snapshot.ControlRoutes {
		if normalizeHost(snapshot.ControlRoutes[i].Hostname) == host {
			selected = &snapshot.ControlRoutes[i]
			target = controlTarget
			break
		}
	}
	if selected == nil {
		for i := range snapshot.BusinessRoutes {
			if normalizeHost(snapshot.BusinessRoutes[i].Hostname) == host {
				selected = &snapshot.BusinessRoutes[i]
				break
			}
		}
	}
	if selected == nil {
		http.Error(w, "route not found", http.StatusNotFound)
		return
	}
	if selected.Status != "active" {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	if req.TLS == nil && selected.HTTPRedirect {
		location := url.URL{Scheme: "https", Host: normalizeHost(selected.Hostname), Path: req.URL.Path, RawQuery: req.URL.RawQuery}
		http.Redirect(w, req, location.String(), http.StatusPermanentRedirect)
		return
	}
	if req.ContentLength > maxRouterBodyBytes {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	if req.Body != nil {
		req.Body = http.MaxBytesReader(w, req.Body, maxRouterBodyBytes)
	}
	proxy := httputil.NewSingleHostReverseProxy(&target)
	proxy.Transport = r.transport
	originalDirector := proxy.Director
	proxy.Director = func(out *http.Request) {
		stripForwardedHeaders(out.Header)
		originalDirector(out)
		out.Host = req.Host
		out.Header.Set("X-Forwarded-Proto", requestProto(req))
		if clientIP := requestClientIP(req); clientIP != "" {
			out.Header.Set("X-Forwarded-For", clientIP)
		}
	}
	proxy.ErrorHandler = func(out http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(out, "upstream unavailable", http.StatusBadGateway)
	}
	proxy.ServeHTTP(w, req)
}

func routerTransport() http.RoundTripper {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.ResponseHeaderTimeout = 15 * time.Second
	transport.ExpectContinueTimeout = 1 * time.Second
	transport.IdleConnTimeout = 90 * time.Second
	return transport
}

func requestHeaderBytes(req *http.Request) int {
	if req == nil {
		return 0
	}
	total := len(req.Method) + len(req.RequestURI) + len(req.Proto) + 4
	for name, values := range req.Header {
		total += len(name) + 2
		for _, value := range values {
			total += len(value) + 2
		}
	}
	return total
}

func stripForwardedHeaders(header http.Header) {
	for _, name := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"} {
		header.Del(name)
	}
}

func normalizeHost(value string) string {
	value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if host, _, err := netSplitHostPort(value); err == nil {
		return strings.TrimSuffix(host, ".")
	}
	return value
}

func netSplitHostPort(value string) (string, string, error) {
	// Keep the runtime package free of address parsing policy: Hostname's
	// bracket form is handled explicitly and ordinary hosts only strip a port
	// when it is unambiguous.
	if strings.HasPrefix(value, "[") {
		end := strings.Index(value, "]")
		if end > 0 && len(value) > end+2 && value[end+1] == ':' {
			return value[1:end], value[end+2:], nil
		}
		return "", "", errors.New("not host:port")
	}
	parts := strings.Split(value, ":")
	if len(parts) == 2 && parts[1] != "" {
		return parts[0], parts[1], nil
	}
	return "", "", errors.New("not host:port")
}

func requestProto(req *http.Request) string {
	if req.TLS != nil {
		return "https"
	}
	return "http"
}

func requestClientIP(req *http.Request) string {
	value := req.RemoteAddr
	if host, _, err := netSplitHostPort(value); err == nil {
		return host
	}
	return value
}

// TLSConfig allows a caller to add SNI-aware certificates without exposing
// certificate storage or database access to Runtime. Unknown SNI is rejected
// by returning an error from GetCertificate.
func TLSConfig(certificates map[string]tls.Certificate) *tls.Config {
	store := NewCertificateStore()
	store.Replace(certificates)
	return store.TLSConfig()
}

func normalizeSNI(value string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
}

var _ http.Handler = (*Runtime)(nil)
