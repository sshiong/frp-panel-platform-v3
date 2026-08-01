package router

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
)

type Runtime struct {
	mu       sync.RWMutex
	key      []byte
	current  Snapshot
	control  *url.URL
	business *url.URL
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
	return &Runtime{key: append([]byte(nil), key...), control: control, business: business}, nil
}

func (r *Runtime) LoadFile(path string) error {
	content, err := os.ReadFile(path)
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
		location := "https://" + req.Host
		if req.URL.RequestURI() != "" {
			location += req.URL.RequestURI()
		}
		http.Redirect(w, req, location, http.StatusPermanentRedirect)
		return
	}
	proxy := httputil.NewSingleHostReverseProxy(&target)
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
	return &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert, ok := certificates[strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))]
		if !ok {
			return nil, errors.New("unknown SNI")
		}
		return &cert, nil
	}}
}

var _ http.Handler = (*Runtime)(nil)
