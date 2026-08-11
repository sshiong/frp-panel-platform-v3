package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/ricardo/frp-panel-platform/client/internal/config"
	"github.com/ricardo/frp-panel-platform/client/internal/id"
	"github.com/ricardo/frp-panel-platform/client/internal/security"
	"github.com/ricardo/frp-panel-platform/client/internal/supervisor"
	"github.com/ricardo/frp-panel-platform/client/internal/version"
)

type App struct {
	Config              config.Config
	Supervisor          *supervisor.Supervisor
	mu                  sync.RWMutex
	serverURL           string
	serverToken         string
	serverSPKIPin       string
	serverReachable     bool
	runtimeCredential   string
	frpUsername         string
	frpSecret           string
	frpsTransportSecret string
	localSession        string
	csrfToken           string
	user                map[string]interface{}
	expiresAt           time.Time
	lastCache           map[string]json.RawMessage
	lastConfig          supervisor.Snapshot
	wsMu                sync.Mutex
	wsConn              *websocket.Conn
	wsCancel            context.CancelFunc
	wsGeneration        uint64
}

type ClientSession struct {
	CSRFToken            string                 `json:"csrf_token"`
	User                 map[string]interface{} `json:"user"`
	ServerPanelURL       string                 `json:"server_panel_url"`
	ExpiresAt            time.Time              `json:"expires_at"`
	ServerVersion        string                 `json:"server_version,omitempty"`
	MinimumClientVersion string                 `json:"minimum_client_version,omitempty"`
	LatestClientVersion  string                 `json:"latest_client_version,omitempty"`
	UpgradeRequired      bool                   `json:"upgrade_required,omitempty"`
	UpgradeSuggested     bool                   `json:"upgrade_suggested,omitempty"`
}

type RemoteError struct {
	Status               int
	Code                 string
	Detail               string
	UpgradeRequired      bool
	ClientVersion        string
	MinimumClientVersion string
	LatestClientVersion  string
}

type ServerCompatibility struct {
	ServerVersion        string `json:"server_version"`
	MinimumClientVersion string `json:"minimum_client_version"`
	LatestClientVersion  string `json:"latest_client_version"`
	MinimumFRPCVersion   string `json:"minimum_frpc_version"`
	ProtocolVersion      string `json:"protocol_version"`
	ConfigSchemaVersion  string `json:"config_schema_version"`
}

type wsEnvelope struct {
	MessageID       string      `json:"message_id"`
	ProtocolVersion string      `json:"protocol_version"`
	Timestamp       time.Time   `json:"timestamp"`
	Type            string      `json:"type"`
	Payload         interface{} `json:"payload,omitempty"`
}

// serverHTTPClient deliberately does not follow redirects. The Server URL is
// configured by the user and requests may carry the opaque session token; a
// redirect should be surfaced as an error response rather than becoming a
// second request to an unexpected endpoint.
var serverHTTPClient = &http.Client{
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func (e RemoteError) Error() string {
	if e.Detail != "" {
		return e.Detail
	}
	return e.Code
}

func New(cfg config.Config) *App {
	return &App{Config: cfg, Supervisor: supervisor.NewWithBinaryHashAndVersion(cfg.DataDir, cfg.FRPCBinary, cfg.FRPCBinarySHA256, cfg.FRPCVersion), lastCache: make(map[string]json.RawMessage)}
}

func (a *App) Login(ctx context.Context, serverURL, username, password string) (ClientSession, error) {
	return a.LoginWithTrust(ctx, serverURL, username, password, "")
}

// LoginWithTrust performs the only password-bearing request. A non-empty
// fingerprint is used only after the local UI has displayed it and the user
// has explicitly confirmed the certificate. It is held in memory with the
// Server Session and never persisted to browser storage.
func (a *App) LoginWithTrust(ctx context.Context, serverURL, username, password, trustedSPKI string) (ClientSession, error) {
	normalized, err := security.NormalizeServerURL(serverURL, a.Config.Environment == "development")
	if err != nil {
		return ClientSession{}, err
	}
	trustedSPKI, err = security.NormalizeSPKIHash(trustedSPKI)
	if err != nil {
		return ClientSession{}, err
	}
	a.mu.RLock()
	oldToken, oldURL, oldPin := a.serverToken, a.serverURL, a.serverSPKIPin
	a.mu.RUnlock()
	if trustedSPKI == "" && oldURL == normalized {
		trustedSPKI = oldPin
	}
	var response struct {
		Token               string                 `json:"token"`
		User                map[string]interface{} `json:"user"`
		SessionExpiresAt    time.Time              `json:"session_expires_at"`
		RuntimeCredential   string                 `json:"runtime_credential"`
		FRPUsername         string                 `json:"frp_username"`
		FRPSecret           string                 `json:"frp_secret"`
		FRPSTransportSecret string                 `json:"frps_transport_secret"`
	}
	var compatibility ServerCompatibility
	if err := a.serverRequestWithPin(ctx, normalized, trustedSPKI, "GET", "/api/v1/compatibility", nil, "", &compatibility); err != nil {
		var remote RemoteError
		if !errors.As(err, &remote) || remote.Status != http.StatusNotFound {
			return ClientSession{}, err
		}
	}
	if err := a.serverRequestWithPin(ctx, normalized, trustedSPKI, "POST", "/api/v1/auth/client-login", map[string]string{"username": username, "password": password}, "", &response); err != nil {
		return ClientSession{}, err
	}
	if response.Token == "" {
		return ClientSession{}, fmt.Errorf("server did not return a session")
	}
	// A successful login is the commit point for switching Server Panels. Best
	// effort logout of the previous opaque session happens before the new
	// credentials replace local memory; a failure must never prevent the safe
	// switch because the old Server may already be unreachable.
	if oldToken != "" && oldURL != "" {
		_ = a.serverRequestWithPin(ctx, oldURL, oldPin, "POST", "/api/v1/auth/logout", nil, oldToken, nil)
	}
	a.stopWebSocket()
	local, err := randomToken()
	if err != nil {
		return ClientSession{}, err
	}
	csrf, err := randomToken()
	if err != nil {
		return ClientSession{}, err
	}
	a.mu.Lock()
	a.serverURL = normalized
	a.serverToken = response.Token
	a.serverSPKIPin = trustedSPKI
	a.serverReachable = true
	a.runtimeCredential = response.RuntimeCredential
	a.frpUsername = response.FRPUsername
	a.frpSecret = response.FRPSecret
	a.frpsTransportSecret = response.FRPSTransportSecret
	a.localSession = local
	a.csrfToken = csrf
	a.user = response.User
	a.expiresAt = time.Now().UTC().Add(30 * time.Minute)
	// Cached snapshots and last-good UI state belong to the previous local
	// session, even when the user logs into the same Server URL again.
	a.lastCache = make(map[string]json.RawMessage)
	a.lastConfig = supervisor.Snapshot{}
	a.mu.Unlock()
	if oldToken != "" {
		_ = a.Supervisor.Stop(ctx)
		_ = a.Supervisor.ClearRuntimeSecrets()
	}
	if snapshot, err := a.fetchConfig(ctx); err == nil {
		_ = a.applySnapshot(ctx, snapshot)
	}
	a.startWebSocket()
	upgradeRequired := compatibility.MinimumClientVersion != "" && !version.IsAtLeast(version.ClientVersion, compatibility.MinimumClientVersion)
	upgradeSuggested := !upgradeRequired && compatibility.LatestClientVersion != "" && version.CompareVersionStrings(version.ClientVersion, compatibility.LatestClientVersion) < 0
	return ClientSession{CSRFToken: csrf, User: response.User, ServerPanelURL: normalized, ExpiresAt: a.expiresAt, ServerVersion: compatibility.ServerVersion, MinimumClientVersion: compatibility.MinimumClientVersion, LatestClientVersion: compatibility.LatestClientVersion, UpgradeRequired: upgradeRequired, UpgradeSuggested: upgradeSuggested}, nil
}

func (a *App) Logout(ctx context.Context) error {
	a.stopWebSocket()
	a.mu.RLock()
	token, urlValue, pin := a.serverToken, a.serverURL, a.serverSPKIPin
	a.mu.RUnlock()
	if token != "" {
		_ = a.serverRequestWithPin(ctx, urlValue, pin, "POST", "/api/v1/auth/logout", nil, token, nil)
	}
	_ = a.Supervisor.Stop(ctx)
	_ = a.Supervisor.ClearRuntimeSecrets()
	a.mu.Lock()
	a.serverToken = ""
	a.serverURL = ""
	a.serverSPKIPin = ""
	a.serverReachable = false
	a.runtimeCredential = ""
	a.frpUsername = ""
	a.frpSecret = ""
	a.frpsTransportSecret = ""
	a.localSession = ""
	a.csrfToken = ""
	a.user = nil
	a.expiresAt = time.Time{}
	a.lastConfig = supervisor.Snapshot{}
	a.lastCache = make(map[string]json.RawMessage)
	a.mu.Unlock()
	return nil
}

func (a *App) ValidateLocal(cookie string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return cookie != "" && cookie == a.localSession && !a.expiresAt.IsZero() && time.Now().UTC().Before(a.expiresAt)
}
func (a *App) CSRFValid(value string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return value != "" && value == a.csrfToken
}
func (a *App) SessionCookie() string { a.mu.RLock(); defer a.mu.RUnlock(); return a.localSession }
func (a *App) Session() ClientSession {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return ClientSession{CSRFToken: a.csrfToken, User: a.user, ServerPanelURL: a.serverURL, ExpiresAt: a.expiresAt}
}

// ServerReachable reports whether the last Server-backed read succeeded. It
// is intentionally only a local UI hint; authorization continues to be
// enforced by the Server session on every proxied request.
func (a *App) ServerReachable() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.serverReachable
}

// InspectServerCertificate is deliberately independent of the authenticated
// session. The local UI can call it before a password-bearing login request.
func (a *App) InspectServerCertificate(ctx context.Context, serverURL string) (security.CertificateInfo, error) {
	normalized, err := security.NormalizeServerURL(serverURL, a.Config.Environment == "development")
	if err != nil {
		return security.CertificateInfo{}, err
	}
	return security.InspectServerCertificate(ctx, normalized)
}

func (a *App) Proxy(ctx context.Context, method, path string, body interface{}, csrf string, response interface{}, idempotencyKeys ...string) error {
	a.mu.RLock()
	token, urlValue, pin := a.serverToken, a.serverURL, a.serverSPKIPin
	a.mu.RUnlock()
	if token == "" || urlValue == "" {
		if method == "GET" && a.loadCached(path, response) {
			a.setServerReachable(false)
			return nil
		}
		return fmt.Errorf("client session is offline")
	}
	if method != "GET" && method != "HEAD" && !a.CSRFValid(csrf) {
		return fmt.Errorf("local csrf validation failed")
	}
	err := a.serverRequestWithPin(ctx, urlValue, pin, method, path, body, token, response, idempotencyKeys...)
	if err != nil {
		var remote RemoteError
		if errors.As(err, &remote) {
			if remote.Code == "SESSION_REPLACED" || remote.Code == "SESSION_EXPIRED" || remote.Code == "AUTH_USER_DISABLED" {
				// A replaced/revoked Server Session is a local safety event: stop FRPC
				// before returning the error and erase all runtime-only material. Never
				// let an offline cache hide a server-side session invalidation.
				a.invalidateRemoteSession(ctx)
			}
			// A client-side cache is only valid for transport/server unavailability;
			// it must not mask authorization or validation responses from the Server.
			if remote.Status < http.StatusInternalServerError {
				return err
			}
		}
		if method == "GET" && a.loadCached(path, response) {
			a.setServerReachable(false)
			return nil
		}
	}
	if err == nil {
		a.setServerReachable(true)
		a.cacheResponse(path, response)
	}
	return err
}

func (a *App) setServerReachable(value bool) {
	a.mu.Lock()
	a.serverReachable = value
	a.mu.Unlock()
}

func (a *App) cacheResponse(path string, response interface{}) {
	if response == nil || (path != "/api/v1/dashboard" && path != "/api/v1/mappings" && path != "/api/v1/domains" && path != "/api/v1/operations" && path != "/api/v1/config/full") {
		return
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		return
	}
	a.mu.Lock()
	if a.lastCache == nil {
		a.lastCache = make(map[string]json.RawMessage)
	}
	a.lastCache[path] = append(json.RawMessage(nil), encoded...)
	a.mu.Unlock()
}

func (a *App) loadCached(path string, response interface{}) bool {
	if response == nil {
		return false
	}
	a.mu.RLock()
	encoded, ok := a.lastCache[path]
	copyOfEncoded := append(json.RawMessage(nil), encoded...)
	a.mu.RUnlock()
	if !ok || len(copyOfEncoded) == 0 {
		return false
	}
	return json.Unmarshal(copyOfEncoded, response) == nil
}

func (a *App) FetchConfigAndApply(ctx context.Context) error {
	snapshot, err := a.fetchConfig(ctx)
	if err != nil {
		return err
	}
	return a.applySnapshot(ctx, snapshot)
}
func (a *App) SupervisorStatus() supervisor.Status { return a.Supervisor.Status() }

func (a *App) fetchConfig(ctx context.Context) (supervisor.Snapshot, error) {
	var snapshot supervisor.Snapshot
	if err := a.Proxy(ctx, "GET", "/api/v1/config/full", nil, "", &snapshot); err != nil {
		return snapshot, err
	}
	a.mu.RLock()
	token, serverURL := a.serverToken, a.serverURL
	a.mu.RUnlock()
	var keyResponse struct {
		PublicKey string `json:"public_key"`
	}
	if err := a.serverRequest(ctx, serverURL, "GET", "/api/v1/config/signing-key", nil, token, &keyResponse); err != nil {
		return snapshot, err
	}
	publicKeyBytes, err := hex.DecodeString(keyResponse.PublicKey)
	if err != nil || len(publicKeyBytes) != ed25519.PublicKeySize || !supervisor.VerifySnapshot(snapshot, ed25519.PublicKey(publicKeyBytes)) {
		return snapshot, fmt.Errorf("config signature verification failed")
	}
	return snapshot, nil
}
func (a *App) applySnapshot(ctx context.Context, snapshot supervisor.Snapshot) error {
	a.mu.RLock()
	payload := make(map[string]interface{}, len(snapshot.Payload)+5)
	for key, value := range snapshot.Payload {
		payload[key] = value
	}
	payload["frp_username"] = a.frpUsername
	payload["frp_secret"] = a.frpSecret
	payload["frp_user_secret"] = a.frpSecret
	payload["frps_transport_secret"] = a.frpsTransportSecret
	payload["runtime_credential"] = a.runtimeCredential
	a.mu.RUnlock()
	snapshot.Payload = payload
	a.mu.Lock()
	a.lastConfig = snapshot
	a.mu.Unlock()
	err := a.Supervisor.Apply(ctx, snapshot)
	input := map[string]interface{}{"status": "succeeded", "config_version": snapshot.ConfigVersion, "applied_config_hash": snapshot.ConfigHash, "client_panel_version": version.ClientVersion, "frpc_version": a.Config.FRPCVersion}
	if err != nil {
		input["status"] = "failed"
		input["error_code"] = "FRPC_VERIFY_FAILED"
		input["error_message"] = err.Error()
	}
	a.mu.RLock()
	token, serverURL := a.serverToken, a.serverURL
	a.mu.RUnlock()
	// This is a Client Supervisor-to-Server call, not a browser write. It uses the
	// in-memory opaque Server Session and never passes through the local web CSRF gate.
	_ = a.serverRequest(ctx, serverURL, "POST", "/api/v1/config/apply-result", input, token, &map[string]interface{}{})
	return err
}

func (a *App) serverRequest(ctx context.Context, baseURL, method, path string, payload interface{}, token string, response interface{}, idempotencyKeys ...string) error {
	pin := ""
	a.mu.RLock()
	if strings.TrimRight(baseURL, "/") == strings.TrimRight(a.serverURL, "/") {
		pin = a.serverSPKIPin
	}
	a.mu.RUnlock()
	return a.serverRequestWithPin(ctx, baseURL, pin, method, path, payload, token, response, idempotencyKeys...)
}

func (a *App) serverRequestWithPin(ctx context.Context, baseURL, pin, method, path string, payload interface{}, token string, response interface{}, idempotencyKeys ...string) error {
	var reader io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(encoded)
	}
	requestURL, err := url.JoinPath(strings.TrimRight(baseURL, "/"), path)
	if err != nil {
		return err
	}
	requestCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, method, requestURL, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("X-FRP-Protocol-Version", "v1")
	req.Header.Set("X-FRP-Client-Version", version.ClientVersion)
	req.Header.Set("X-Request-ID", id.New())
	if method == "POST" || method == "PUT" || method == "DELETE" {
		idempotencyKey := ""
		if len(idempotencyKeys) > 0 {
			idempotencyKey = strings.TrimSpace(idempotencyKeys[0])
		}
		if idempotencyKey == "" {
			idempotencyKey = id.New()
		}
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	client, err := serverHTTPClientFor(baseURL, pin)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var p struct {
			Code                 string `json:"code"`
			Detail               string `json:"detail"`
			UpgradeRequired      bool   `json:"upgrade_required"`
			ClientVersion        string `json:"client_version"`
			MinimumClientVersion string `json:"minimum_client_version"`
			LatestClientVersion  string `json:"latest_client_version"`
		}
		_ = json.Unmarshal(data, &p)
		return RemoteError{Status: resp.StatusCode, Code: p.Code, Detail: p.Detail, UpgradeRequired: p.UpgradeRequired, ClientVersion: p.ClientVersion, MinimumClientVersion: p.MinimumClientVersion, LatestClientVersion: p.LatestClientVersion}
	}
	if response != nil && len(data) > 0 {
		return json.Unmarshal(data, response)
	}
	return nil
}

func serverHTTPClientFor(baseURL, pin string) (*http.Client, error) {
	if strings.TrimSpace(pin) == "" {
		return serverHTTPClient, nil
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" {
		return nil, fmt.Errorf("certificate pin requires an https Server Panel address")
	}
	tlsConfig, err := security.PinnedTLSConfig(parsed.Hostname(), pin)
	if err != nil {
		return nil, err
	}
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("default HTTP transport is unavailable")
	}
	transport = transport.Clone()
	transport.TLSClientConfig = tlsConfig
	return &http.Client{Transport: transport, CheckRedirect: serverHTTPClient.CheckRedirect}, nil
}

func randomToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func (a *App) startWebSocket() {
	a.wsMu.Lock()
	if a.wsCancel != nil {
		a.wsCancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.wsGeneration++
	generation := a.wsGeneration
	a.wsCancel = cancel
	a.wsMu.Unlock()
	go a.runWebSocket(ctx, generation)
}

func (a *App) stopWebSocket() {
	a.wsMu.Lock()
	if a.wsCancel != nil {
		a.wsCancel()
	}
	a.wsCancel = nil
	a.wsGeneration++
	conn := a.wsConn
	a.wsConn = nil
	a.wsMu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}

func (a *App) currentWebSocket(generation uint64) bool {
	a.wsMu.Lock()
	defer a.wsMu.Unlock()
	return a.wsGeneration == generation && a.wsCancel != nil
}

func (a *App) installWebSocket(generation uint64, conn *websocket.Conn) bool {
	a.wsMu.Lock()
	defer a.wsMu.Unlock()
	if a.wsGeneration != generation || a.wsCancel == nil {
		return false
	}
	a.wsConn = conn
	return true
}

func (a *App) clearWebSocket(generation uint64, conn *websocket.Conn) {
	a.wsMu.Lock()
	defer a.wsMu.Unlock()
	if a.wsGeneration == generation && a.wsConn == conn {
		a.wsConn = nil
	}
}

func (a *App) runWebSocket(ctx context.Context, generation uint64) {
	backoff := time.Second
	for {
		if err := ctx.Err(); err != nil || !a.currentWebSocket(generation) {
			return
		}
		baseURL, token := a.serverCredentials()
		if baseURL == "" || token == "" {
			return
		}
		conn, response, err := dialServerWebSocketWithPin(ctx, baseURL, token, a.serverCertificatePin(), localOrigin(a.Config))
		if err != nil {
			if response != nil && response.StatusCode == http.StatusUnauthorized && a.currentWebSocket(generation) {
				a.invalidateRemoteSession(context.Background())
				return
			}
			if !waitWebSocket(ctx, backoff) {
				return
			}
			if backoff < 60*time.Second {
				backoff *= 2
				if backoff > 60*time.Second {
					backoff = 60 * time.Second
				}
			}
			continue
		}
		backoff = time.Second
		if !a.installWebSocket(generation, conn) {
			_ = conn.Close()
			return
		}
		invalidated := a.runWebSocketConnection(ctx, conn, generation)
		a.clearWebSocket(generation, conn)
		_ = conn.Close()
		if invalidated || ctx.Err() != nil || !a.currentWebSocket(generation) {
			return
		}
		if !waitWebSocket(ctx, backoff) {
			return
		}
		if backoff < 60*time.Second {
			backoff *= 2
			if backoff > 60*time.Second {
				backoff = 60 * time.Second
			}
		}
	}
}

func (a *App) runWebSocketConnection(ctx context.Context, conn *websocket.Conn, generation uint64) bool {
	connectionCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var writeMu sync.Mutex
	write := func(messageType string, payload interface{}) error {
		message := wsEnvelope{MessageID: id.New(), ProtocolVersion: "v1", Timestamp: time.Now().UTC(), Type: messageType, Payload: payload}
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		return conn.WriteJSON(message)
	}
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		ticker := time.NewTicker(20 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := write("heartbeat", map[string]interface{}{"client_time": time.Now().UTC()}); err != nil {
					_ = conn.Close()
					cancel()
					return
				}
			case <-connectionCtx.Done():
				return
			}
		}
	}()
	defer func() {
		cancel()
		_ = conn.Close()
		<-writerDone
	}()
	for {
		if !a.currentWebSocket(generation) {
			return true
		}
		_ = conn.SetReadDeadline(time.Now().Add(45 * time.Second))
		var message wsEnvelope
		if err := conn.ReadJSON(&message); err != nil {
			return false
		}
		if !a.currentWebSocket(generation) {
			return true
		}
		switch message.Type {
		case "session_replaced", "session_expired", "user_disabled", "frp_secret_rotated":
			a.invalidateRemoteSession(context.Background())
			return true
		case "shutdown_frpc":
			_ = a.Supervisor.Stop(context.Background())
			_ = a.Supervisor.ClearRuntimeSecrets()
		case "config_version_changed", "force_full_sync", "mapping_deleted":
			syncCtx, syncCancel := context.WithTimeout(context.Background(), 20*time.Second)
			_ = a.FetchConfigAndApply(syncCtx)
			syncCancel()
		}
	}
}

func (a *App) invalidateRemoteSession(ctx context.Context) {
	a.stopWebSocket()
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = a.Supervisor.Stop(cleanupCtx)
	_ = a.Supervisor.ClearRuntimeSecrets()
	a.mu.Lock()
	a.serverToken = ""
	a.serverURL = ""
	a.serverSPKIPin = ""
	a.runtimeCredential = ""
	a.frpUsername = ""
	a.frpSecret = ""
	a.localSession = ""
	a.csrfToken = ""
	a.user = nil
	a.expiresAt = time.Time{}
	a.lastConfig = supervisor.Snapshot{}
	a.lastCache = make(map[string]json.RawMessage)
	a.serverReachable = false
	a.mu.Unlock()
	_ = ctx
}

func (a *App) serverCredentials() (string, string) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.serverURL, a.serverToken
}

func (a *App) serverCertificatePin() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.serverSPKIPin
}

func dialServerWebSocket(ctx context.Context, baseURL, token, origin string) (*websocket.Conn, *http.Response, error) {
	return dialServerWebSocketWithPin(ctx, baseURL, token, "", origin)
}

func dialServerWebSocketWithPin(ctx context.Context, baseURL, token, pin, origin string) (*websocket.Conn, *http.Response, error) {
	wsURL, err := websocketURL(baseURL)
	if err != nil {
		return nil, nil, err
	}
	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+token)
	headers.Set("X-FRP-Protocol-Version", "v1")
	if origin != "" {
		headers.Set("Origin", origin)
	}
	dialer := websocket.Dialer{HandshakeTimeout: 10 * time.Second}
	if strings.TrimSpace(pin) != "" {
		parsed, parseErr := url.Parse(baseURL)
		if parseErr != nil {
			return nil, nil, parseErr
		}
		dialer.TLSClientConfig, err = security.PinnedTLSConfig(parsed.Hostname(), pin)
		if err != nil {
			return nil, nil, err
		}
	}
	return dialer.DialContext(ctx, wsURL, headers)
}

func websocketURL(baseURL string) (string, error) {
	parsed, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || parsed.Host == "" {
		if err == nil {
			err = fmt.Errorf("server URL has no host")
		}
		return "", err
	}
	switch parsed.Scheme {
	case "http":
		parsed.Scheme = "ws"
	case "https":
		parsed.Scheme = "wss"
	default:
		return "", fmt.Errorf("unsupported server URL scheme %q", parsed.Scheme)
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/api/v1/ws"
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

func localOrigin(cfg config.Config) string {
	host, port, err := net.SplitHostPort(cfg.ListenAddr)
	if err != nil || port == "" {
		return ""
	}
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		host = "127.0.0.1"
	}
	scheme := "http"
	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		scheme = "https"
	}
	return scheme + "://" + net.JoinHostPort(host, port)
}

func waitWebSocket(ctx context.Context, delay time.Duration) bool {
	delay = jitter(delay)
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func jitter(delay time.Duration) time.Duration {
	if delay <= 0 {
		return time.Second
	}
	var sample [1]byte
	if _, err := rand.Read(sample[:]); err != nil {
		return delay
	}
	// Keep reconnects within 80%-120% of the exponential delay.
	return delay * time.Duration(80+int(sample[0])%41) / 100
}
