package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/ricardo/frp-panel-platform/client/internal/config"
	"github.com/ricardo/frp-panel-platform/client/internal/security"
	"github.com/ricardo/frp-panel-platform/client/internal/supervisor"
)

type App struct {
	Config            config.Config
	Supervisor        *supervisor.Supervisor
	mu                sync.RWMutex
	serverURL         string
	serverToken       string
	runtimeCredential string
	frpUsername       string
	frpSecret         string
	localSession      string
	csrfToken         string
	user              map[string]interface{}
	expiresAt         time.Time
	lastDashboard     json.RawMessage
	lastConfig        supervisor.Snapshot
}

type ClientSession struct {
	CSRFToken      string                 `json:"csrf_token"`
	User           map[string]interface{} `json:"user"`
	ServerPanelURL string                 `json:"server_panel_url"`
	ExpiresAt      time.Time              `json:"expires_at"`
}

type RemoteError struct {
	Status int
	Code   string
	Detail string
}

func (e RemoteError) Error() string {
	if e.Detail != "" {
		return e.Detail
	}
	return e.Code
}

func New(cfg config.Config) *App {
	return &App{Config: cfg, Supervisor: supervisor.NewWithBinaryHash(cfg.DataDir, cfg.FRPCBinary, cfg.FRPCBinarySHA256)}
}

func (a *App) Login(ctx context.Context, serverURL, username, password string) (ClientSession, error) {
	normalized, err := security.NormalizeServerURL(serverURL, a.Config.Environment == "development")
	if err != nil {
		return ClientSession{}, err
	}
	var response struct {
		Token             string                 `json:"token"`
		User              map[string]interface{} `json:"user"`
		SessionExpiresAt  time.Time              `json:"session_expires_at"`
		RuntimeCredential string                 `json:"runtime_credential"`
		FRPUsername       string                 `json:"frp_username"`
		FRPSecret         string                 `json:"frp_secret"`
	}
	if err := a.serverRequest(ctx, normalized, "POST", "/api/v1/auth/client-login", map[string]string{"username": username, "password": password}, "", &response); err != nil {
		return ClientSession{}, err
	}
	if response.Token == "" {
		return ClientSession{}, fmt.Errorf("server did not return a session")
	}
	local, err := randomToken()
	if err != nil {
		return ClientSession{}, err
	}
	csrf, err := randomToken()
	if err != nil {
		return ClientSession{}, err
	}
	a.mu.Lock()
	oldToken := a.serverToken
	a.serverURL = normalized
	a.serverToken = response.Token
	a.runtimeCredential = response.RuntimeCredential
	a.frpUsername = response.FRPUsername
	a.frpSecret = response.FRPSecret
	a.localSession = local
	a.csrfToken = csrf
	a.user = response.User
	a.expiresAt = time.Now().UTC().Add(30 * time.Minute)
	a.mu.Unlock()
	if oldToken != "" {
		_ = a.Supervisor.Stop(ctx)
		_ = a.Supervisor.ClearRuntimeSecrets()
	}
	if snapshot, err := a.fetchConfig(ctx); err == nil {
		_ = a.applySnapshot(ctx, snapshot)
	}
	return ClientSession{CSRFToken: csrf, User: response.User, ServerPanelURL: normalized, ExpiresAt: a.expiresAt}, nil
}

func (a *App) Logout(ctx context.Context) error {
	a.mu.RLock()
	token, urlValue := a.serverToken, a.serverURL
	a.mu.RUnlock()
	if token != "" {
		_ = a.serverRequest(ctx, urlValue, "POST", "/api/v1/auth/logout", nil, token, nil)
	}
	_ = a.Supervisor.Stop(ctx)
	_ = a.Supervisor.ClearRuntimeSecrets()
	a.mu.Lock()
	a.serverToken = ""
	a.serverURL = ""
	a.runtimeCredential = ""
	a.frpUsername = ""
	a.frpSecret = ""
	a.localSession = ""
	a.csrfToken = ""
	a.user = nil
	a.expiresAt = time.Time{}
	a.lastConfig = supervisor.Snapshot{}
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

func (a *App) Proxy(ctx context.Context, method, path string, body interface{}, csrf string, response interface{}) error {
	a.mu.RLock()
	token, urlValue := a.serverToken, a.serverURL
	a.mu.RUnlock()
	if token == "" || urlValue == "" {
		if a.lastDashboard != nil && method == "GET" && path == "/api/v1/dashboard" {
			return json.Unmarshal(a.lastDashboard, response)
		}
		return fmt.Errorf("client session is offline")
	}
	if method != "GET" && method != "HEAD" && !a.CSRFValid(csrf) {
		return fmt.Errorf("local csrf validation failed")
	}
	err := a.serverRequest(ctx, urlValue, method, path, body, token, response)
	if remote, ok := err.(RemoteError); ok && (remote.Code == "SESSION_REPLACED" || remote.Code == "SESSION_EXPIRED" || remote.Code == "AUTH_USER_DISABLED") {
		// A replaced/revoked Server Session is a local safety event: stop FRPC
		// before returning the error and erase all runtime-only material.
		_ = a.Supervisor.Stop(ctx)
		_ = a.Supervisor.ClearRuntimeSecrets()
		a.mu.Lock()
		a.serverToken = ""
		a.serverURL = ""
		a.runtimeCredential = ""
		a.frpUsername = ""
		a.frpSecret = ""
		a.localSession = ""
		a.csrfToken = ""
		a.user = nil
		a.expiresAt = time.Time{}
		a.mu.Unlock()
	}
	if err == nil && path == "/api/v1/dashboard" {
		a.mu.Lock()
		encoded, _ := json.Marshal(response)
		a.lastDashboard = encoded
		a.mu.Unlock()
	}
	return err
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
	payload["server_addr"] = a.serverURL
	payload["frp_username"] = a.frpUsername
	payload["frp_secret"] = a.frpSecret
	payload["runtime_credential"] = a.runtimeCredential
	a.mu.RUnlock()
	snapshot.Payload = payload
	a.mu.Lock()
	a.lastConfig = snapshot
	a.mu.Unlock()
	err := a.Supervisor.Apply(ctx, snapshot)
	input := map[string]interface{}{"status": "succeeded", "config_version": snapshot.ConfigVersion, "applied_config_hash": snapshot.ConfigHash, "client_panel_version": "0.1.0", "frpc_version": "0.52.3"}
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

func (a *App) serverRequest(ctx context.Context, baseURL, method, path string, payload interface{}, token string, response interface{}) error {
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
	req.Header.Set("X-Request-ID", uuid.NewString())
	if method == "POST" || method == "PUT" || method == "DELETE" {
		req.Header.Set("Idempotency-Key", uuid.NewString())
	}
	resp, err := http.DefaultClient.Do(req)
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
			Code   string `json:"code"`
			Detail string `json:"detail"`
		}
		_ = json.Unmarshal(data, &p)
		return RemoteError{Status: resp.StatusCode, Code: p.Code, Detail: p.Detail}
	}
	if response != nil && len(data) > 0 {
		return json.Unmarshal(data, response)
	}
	return nil
}

func randomToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
