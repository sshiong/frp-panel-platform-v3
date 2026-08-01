package httpapi

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"
	"github.com/ricardo/frp-panel-platform/server/internal/backup"
	"github.com/ricardo/frp-panel-platform/server/internal/service"
)

type contextKey string

const (
	authContextKey   contextKey = "auth"
	requestIDKey     contextKey = "request_id"
	cookieAuthKey    contextKey = "cookie_auth"
	serverCSRFCookie            = "frp_server_csrf"
)

type API struct {
	App         *service.App
	Log         *slog.Logger
	Origin      map[string]bool
	WS          websocket.Upgrader
	mu          sync.Mutex
	clients     map[string]map[*websocket.Conn]struct{}
	apiLimit    *requestRateLimiter
	loginLimit  *requestRateLimiter
	concurrency chan struct{}
}

type wsEnvelope struct {
	MessageID       string      `json:"message_id"`
	ProtocolVersion string      `json:"protocol_version"`
	Timestamp       time.Time   `json:"timestamp"`
	Type            string      `json:"type"`
	Payload         interface{} `json:"payload,omitempty"`
}

func New(app *service.App, logger *slog.Logger) *API {
	origins := make(map[string]bool)
	for _, origin := range app.Config.AllowedOrigins {
		origins[origin] = true
	}
	return &API{App: app, Log: logger, Origin: origins, WS: websocket.Upgrader{ReadBufferSize: 4096, WriteBufferSize: 4096, CheckOrigin: func(r *http.Request) bool { return origins[r.Header.Get("Origin")] }}, clients: make(map[string]map[*websocket.Conn]struct{}), apiLimit: newRequestRateLimiter(600, time.Minute), loginLimit: newRequestRateLimiter(10, time.Minute), concurrency: make(chan struct{}, 128)}
}

// RouteManifestHandler exposes the production route tree to repository-level
// contract tooling without constructing a database-backed App. It is not a
// serving entry point; it exists so OpenAPI validation can compare the
// implementation's actual chi routes with contracts/openapi.yaml.
func RouteManifestHandler() http.Handler {
	return RouteManifestRoutes()
}

// RouteManifestRoutes returns the chi route tree so tooling can walk the
// registered method/path pairs without sending requests to a live server.
func RouteManifestRoutes() chi.Router {
	return (&API{Origin: map[string]bool{}, WS: websocket.Upgrader{}}).routeTree()
}

func (a *API) Handler() http.Handler {
	return a.routeTree()
}

func (a *API) routeTree() chi.Router {
	r := chi.NewRouter()
	r.Use(a.requestID, a.securityHeaders, a.cors, a.rateLimit, a.concurrencyLimit, a.accessLog)
	r.Get("/healthz", a.health)
	r.Get("/metrics", a.metrics)
	r.Get("/", a.adminApp)
	r.Handle("/assets/*", http.StripPrefix("/assets/", http.FileServer(http.Dir(filepath.Join(a.webDir(), "assets")))))
	r.Get("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join(a.webDir(), "favicon.svg"))
	})
	r.Handle("/favicon.svg", http.FileServer(http.Dir(a.webDir())))
	r.With(a.loopbackOnly).HandleFunc("/internal/frp/plugin", a.frpPlugin)
	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/compatibility", a.compatibility)
		r.Post("/auth/admin-login", a.adminLogin)
		r.Post("/auth/client-login", a.clientLogin)
		r.Group(func(r chi.Router) {
			r.Use(a.authenticate)
			r.Use(a.requireWriteIdempotency)
			r.Post("/auth/logout", a.logout)
			r.Post("/auth/change-password", a.changePassword)
			r.Post("/auth/reauth", a.reauth)
			r.Post("/auth/reset-frp-credential", a.resetFRPCredential)
			r.Get("/me", a.me)
			r.Get("/dashboard", a.dashboard)
			r.Get("/mappings", a.listMappings)
			r.Post("/mappings", a.createMapping)
			r.Put("/mappings/{id}", a.updateMapping)
			r.Delete("/mappings/{id}", a.deleteMapping)
			r.Post("/mappings/{id}/toggle", a.toggleMapping)
			r.Get("/domains", a.listDomains)
			r.Post("/domains", a.createDomain)
			r.Delete("/domains/{id}", a.deleteDomain)
			r.Post("/domains/{id}/dns-action", a.domainDNSAction)
			r.Get("/config/full", a.fullConfig)
			r.Get("/config/signing-key", a.signingKey)
			r.Post("/config/apply-result", a.applyResult)
			r.Post("/session/heartbeat", a.heartbeat)
			r.Get("/operations", a.operations)
			r.Post("/operations/{id}/retry", a.retryOperation)
			r.With(a.requireAdmin).Get("/cloudflare/status", a.cloudflareStatus)
			r.With(a.requireAdmin).Post("/cloudflare/token", a.cloudflareToken)
			r.With(a.requireAdmin).Delete("/cloudflare/token", a.clearCloudflare)
			r.Get("/ws", a.websocket)
			r.Route("/admin", func(r chi.Router) {
				r.Use(a.requireAdmin)
				r.Get("/users", a.adminUsers)
				r.Post("/users", a.createUser)
				r.Delete("/users/{id}", a.deleteUser)
				r.Post("/users/{id}/status", a.setUserStatus)
				r.Post("/users/{id}/reset-password", a.resetPassword)
				r.Post("/users/{id}/reset-frp-credential", a.adminResetFRPCredential)
				r.Get("/operations", a.adminOperations)
				r.Get("/stats", a.adminStats)
				r.Get("/router/status", a.routerStatus)
				r.Post("/router/rebuild", a.routerRebuild)
				r.Post("/backups", a.createBackup)
			})
		})
	})
	return r
}

func (a *API) rateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.apiLimit != nil {
			if ok, retry := a.apiLimit.allow(remoteIP(r), time.Now().UTC()); !ok {
				seconds := int(retry.Seconds())
				if seconds < 1 {
					seconds = 1
				}
				w.Header().Set("Retry-After", strconv.Itoa(seconds))
				problem(w, r, http.StatusTooManyRequests, "RATE_LIMITED", "请求过于频繁，请稍后重试。", nil)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (a *API) concurrencyLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.concurrency == nil {
			next.ServeHTTP(w, r)
			return
		}
		select {
		case a.concurrency <- struct{}{}:
			defer func() { <-a.concurrency }()
			next.ServeHTTP(w, r)
		default:
			w.Header().Set("Retry-After", "1")
			problem(w, r, http.StatusTooManyRequests, "CONCURRENCY_LIMITED", "并发请求已达到上限，请稍后重试。", nil)
		}
	})
}

func (a *API) requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" || len(id) > 80 {
			id = shortID()
		}
		ctx := context.WithValue(r.Context(), requestIDKey, id)
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (a *API) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self' http://127.0.0.1:5173 http://localhost:5173; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (a *API) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && a.Origin[origin] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Idempotency-Key, X-CSRF-Token, X-Request-ID")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *API) loopbackOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		ip := net.ParseIP(strings.Trim(host, "[]"))
		if ip == nil || !ip.IsLoopback() {
			problem(w, r, http.StatusNotFound, "NOT_FOUND", "资源不存在。", errors.New("internal endpoint is loopback-only"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *API) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		next.ServeHTTP(w, r)
		a.Log.Info("http_request", "request_id", requestID(r), "method", r.Method, "path", r.URL.Path, "duration_ms", time.Since(started).Milliseconds())
	})
}

func (a *API) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		cookieAuth := false
		if token == "" {
			if cookie, err := r.Cookie("frp_server_session"); err == nil {
				token = "Bearer " + cookie.Value
				cookieAuth = true
			}
		}
		ac, err := a.App.Authenticate(r.Context(), token)
		if err != nil {
			code := "SESSION_EXPIRED"
			if strings.Contains(err.Error(), "replaced") {
				code = "SESSION_REPLACED"
			}
			problem(w, r, http.StatusUnauthorized, code, "当前会话已失效，请重新登录。", err)
			return
		}
		if cookieAuth && r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions && !service.ValidateCSRF(ac, r.Header.Get("X-CSRF-Token")) {
			problem(w, r, http.StatusForbidden, "CSRF_INVALID", "请求校验失败，请刷新面板。", nil)
			return
		}
		ctx := context.WithValue(r.Context(), authContextKey, ac)
		ctx = context.WithValue(ctx, cookieAuthKey, cookieAuth)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (a *API) requireWriteIdempotency(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		protectedResourceWrite := strings.HasPrefix(r.URL.Path, "/api/v1/mappings") || strings.HasPrefix(r.URL.Path, "/api/v1/domains") || strings.HasSuffix(r.URL.Path, "/reset-frp-credential") || (r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v1/admin/users/"))
		if protectedResourceWrite && (r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete || r.Method == http.MethodPatch) {
			key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
			if len(key) < 16 || len(key) > 128 {
				problem(w, r, http.StatusPreconditionRequired, "IDEMPOTENCY_KEY_REQUIRED", "写请求必须携带 16 至 128 字符的 Idempotency-Key。", nil)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (a *API) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ac := authFrom(r)
		if ac.Role != "admin" {
			problem(w, r, http.StatusNotFound, "FORBIDDEN", "资源不存在。", service.ErrForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *API) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "service": "frp-panel-server", "started_at": a.App.Started})
}

func (a *API) metrics(w http.ResponseWriter, r *http.Request) {
	var users, mappings, sessions, portLeases, pendingDomains, pendingCertificates, pendingJobs, routerLag int
	_ = a.App.DB.QueryRowContext(r.Context(), `SELECT COUNT(1) FROM users WHERE status='active'`).Scan(&users)
	_ = a.App.DB.QueryRowContext(r.Context(), `SELECT COUNT(1) FROM mappings WHERE lifecycle_status <> 'deleted'`).Scan(&mappings)
	_ = a.App.DB.QueryRowContext(r.Context(), `SELECT COUNT(1) FROM sessions WHERE revoked_at IS NULL AND expires_at > datetime('now')`).Scan(&sessions)
	_ = a.App.DB.QueryRowContext(r.Context(), `SELECT COUNT(1) FROM port_leases`).Scan(&portLeases)
	_ = a.App.DB.QueryRowContext(r.Context(), `SELECT COUNT(1) FROM domain_bindings WHERE status LIKE 'pending_%' OR status IN ('reserved','deleting')`).Scan(&pendingDomains)
	_ = a.App.DB.QueryRowContext(r.Context(), `SELECT COUNT(1) FROM certificates WHERE status IN ('pending','renewing')`).Scan(&pendingCertificates)
	_ = a.App.DB.QueryRowContext(r.Context(), `SELECT COUNT(1) FROM jobs WHERE status IN ('pending','running','retry_wait')`).Scan(&pendingJobs)
	_ = a.App.DB.QueryRowContext(r.Context(), `SELECT MAX(router_config_version-router_applied_version) FROM router_state`).Scan(&routerLag)
	walBytes := int64(0)
	if info, err := os.Stat(a.App.Config.DBPath + "-wal"); err == nil {
		walBytes = info.Size()
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = fmt.Fprintf(w, "frp_panel_active_users %d\nfrp_panel_mappings %d\nfrp_panel_sessions %d\nfrp_panel_port_leases %d\nfrp_panel_pending_domains %d\nfrp_panel_pending_certificates %d\nfrp_panel_pending_jobs %d\nfrp_panel_router_version_lag %d\nfrp_panel_sqlite_wal_bytes %d\n", users, mappings, sessions, portLeases, pendingDomains, pendingCertificates, pendingJobs, routerLag, walBytes)
}

func (a *API) adminApp(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, filepath.Join(a.webDir(), "index.html"))
}

func (a *API) webDir() string {
	candidates := []string{"web/admin/dist", "../web/admin/dist"}
	if a.App != nil {
		candidates = append([]string{a.App.Config.AdminWebDir}, candidates...)
	}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		absolute, err := filepath.Abs(candidate)
		if err == nil {
			if _, err := os.Stat(filepath.Join(absolute, "index.html")); err == nil {
				return absolute
			}
		}
	}
	return "web/admin/dist"
}

func (a *API) compatibility(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{"protocol_version": "v1", "config_schema_version": "v1", "minimum_client_version": "0.1.0", "latest_client_version": "0.1.0", "minimum_frpc_version": "0.68.0"})
}

func (a *API) adminLogin(w http.ResponseWriter, r *http.Request) {
	var input struct{ Username, Password string }
	if !decodeJSON(w, r, &input) {
		return
	}
	limitKey := "admin|" + remoteIP(r) + "|" + strings.TrimSpace(input.Username)
	if a.loginLimit != nil {
		if ok, retry := a.loginLimit.allow(limitKey, time.Now().UTC()); !ok {
			seconds := int(retry.Seconds())
			if seconds < 1 {
				seconds = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(seconds))
			problem(w, r, http.StatusTooManyRequests, "AUTH_RATE_LIMITED", "登录尝试过于频繁，请稍后重试。", nil)
			return
		}
	}
	result, err := a.App.Login(r.Context(), input.Username, input.Password, "admin_panel", remoteIP(r), r.UserAgent())
	if err != nil {
		problem(w, r, http.StatusUnauthorized, "AUTH_INVALID_CREDENTIALS", "用户名或密码不正确。", err)
		return
	}
	if a.loginLimit != nil {
		a.loginLimit.reset(limitKey)
	}
	http.SetCookie(w, &http.Cookie{Name: "frp_server_session", Value: result.Token, Path: "/", HttpOnly: true, Secure: a.App.Config.Environment == "production", SameSite: http.SameSiteStrictMode, MaxAge: int(time.Until(result.SessionExpires).Seconds())})
	http.SetCookie(w, &http.Cookie{Name: serverCSRFCookie, Value: result.CSRFToken, Path: "/", HttpOnly: false, Secure: a.App.Config.Environment == "production", SameSite: http.SameSiteStrictMode, MaxAge: int(time.Until(result.SessionExpires).Seconds())})
	result.Token = ""
	result.RequestID = requestID(r)
	writeJSON(w, http.StatusOK, result)
}

func (a *API) clientLogin(w http.ResponseWriter, r *http.Request) {
	var input struct{ Username, Password string }
	if !decodeJSON(w, r, &input) {
		return
	}
	limitKey := "client|" + remoteIP(r) + "|" + strings.TrimSpace(input.Username)
	if a.loginLimit != nil {
		if ok, retry := a.loginLimit.allow(limitKey, time.Now().UTC()); !ok {
			seconds := int(retry.Seconds())
			if seconds < 1 {
				seconds = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(seconds))
			problem(w, r, http.StatusTooManyRequests, "AUTH_RATE_LIMITED", "登录尝试过于频繁，请稍后重试。", nil)
			return
		}
	}
	result, err := a.App.Login(r.Context(), input.Username, input.Password, "client_panel", remoteIP(r), r.UserAgent())
	if err != nil {
		code := "AUTH_INVALID_CREDENTIALS"
		if strings.Contains(err.Error(), "disabled") {
			code = "AUTH_USER_DISABLED"
		}
		problem(w, r, http.StatusUnauthorized, code, "用户名或密码不正确，或账号已停用。", err)
		return
	}
	if a.loginLimit != nil {
		a.loginLimit.reset(limitKey)
	}
	result.RequestID = requestID(r)
	a.notifyUser(result.User.ID, "session_replaced", map[string]interface{}{"session_id": result.SessionID})
	writeJSON(w, http.StatusOK, result)
}

func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	ac := authFrom(r)
	if err := a.App.Logout(r.Context(), ac, "USER_LOGOUT"); err != nil {
		problem(w, r, 500, "LOGOUT_FAILED", "退出登录失败。", err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "frp_server_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: a.App.Config.Environment == "production", SameSite: http.SameSiteStrictMode})
	http.SetCookie(w, &http.Cookie{Name: serverCSRFCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: false, Secure: a.App.Config.Environment == "production", SameSite: http.SameSiteStrictMode})
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

func (a *API) changePassword(w http.ResponseWriter, r *http.Request) {
	var input struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if err := a.App.ChangePassword(r.Context(), authFrom(r), input.CurrentPassword, input.NewPassword); err != nil {
		problem(w, r, 400, "PASSWORD_CHANGE_FAILED", "密码修改失败，请检查当前密码和新密码要求。", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

func (a *API) reauth(w http.ResponseWriter, r *http.Request) {
	var input struct {
		CurrentPassword string `json:"current_password"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	ticket, expires, err := a.App.IssueReauthTicket(r.Context(), authFrom(r), input.CurrentPassword)
	if err != nil {
		problem(w, r, http.StatusUnauthorized, "AUTH_INVALID_CREDENTIALS", "当前密码不正确。", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"reauth_ticket": ticket, "expires_at": expires})
}

func (a *API) resetFRPCredential(w http.ResponseWriter, r *http.Request) {
	if mustChange(w, r, authFrom(r)) {
		return
	}
	var input struct {
		ReauthTicket string `json:"reauth_ticket"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if !a.requireReauthTicket(w, r, input.ReauthTicket) {
		return
	}
	result, err := a.App.ResetFRPCredential(r.Context(), authFrom(r), "", input.ReauthTicket, r.Header.Get("Idempotency-Key"))
	if err != nil {
		a.frpResetProblem(w, r, err)
		return
	}
	a.notifyUser(authFrom(r).UserID, "frp_secret_rotated", map[string]interface{}{"secret_version": result.SecretVersion, "session_generation": result.SessionGeneration})
	a.notifyUser(authFrom(r).UserID, "shutdown_frpc", map[string]interface{}{"reason": "frp_secret_rotated"})
	writeJSON(w, http.StatusOK, result)
}

func (a *API) me(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, authFrom(r)) }

func (a *API) dashboard(w http.ResponseWriter, r *http.Request) {
	ac := authFrom(r)
	out, err := a.App.Dashboard(r.Context(), ac)
	if err != nil {
		problem(w, r, 500, "DASHBOARD_FAILED", "无法读取面板状态。", err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) listMappings(w http.ResponseWriter, r *http.Request) {
	items, err := a.App.ListMappings(r.Context(), authFrom(r).UserID)
	if err != nil {
		problem(w, r, 500, "MAPPINGS_READ_FAILED", "无法读取映射。", err)
		return
	}
	var version int64
	_ = a.App.DB.QueryRowContext(r.Context(), `SELECT desired_config_version FROM users WHERE id=?`, authFrom(r).UserID).Scan(&version)
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "config_version": version})
}

func (a *API) createMapping(w http.ResponseWriter, r *http.Request) {
	if mustChange(w, r, authFrom(r)) {
		return
	}
	var input service.MappingRequest
	if !decodeJSON(w, r, &input) {
		return
	}
	item, err := a.App.CreateMapping(r.Context(), authFrom(r), input, r.Header.Get("Idempotency-Key"))
	if err != nil {
		a.mappingProblem(w, r, err)
		return
	}
	a.notifyConfigChanged(authFrom(r).UserID, "mapping", item.ID)
	writeJSON(w, http.StatusCreated, item)
}

func (a *API) updateMapping(w http.ResponseWriter, r *http.Request) {
	if mustChange(w, r, authFrom(r)) {
		return
	}
	var input service.MappingRequest
	if !decodeJSON(w, r, &input) {
		return
	}
	item, err := a.App.UpdateMapping(r.Context(), authFrom(r), chi.URLParam(r, "id"), input, r.Header.Get("Idempotency-Key"))
	if err != nil {
		a.mappingProblem(w, r, err)
		return
	}
	a.notifyConfigChanged(authFrom(r).UserID, "mapping", item.ID)
	writeJSON(w, http.StatusOK, item)
}

func (a *API) deleteMapping(w http.ResponseWriter, r *http.Request) {
	if mustChange(w, r, authFrom(r)) {
		return
	}
	force := r.URL.Query().Get("force") == "true"
	opID, err := a.App.DeleteMapping(r.Context(), authFrom(r), chi.URLParam(r, "id"), force, r.Header.Get("Idempotency-Key"))
	if err != nil {
		a.mappingProblem(w, r, err)
		return
	}
	a.notifyConfigChanged(authFrom(r).UserID, "mapping", chi.URLParam(r, "id"))
	a.notifyUser(authFrom(r).UserID, "mapping_deleted", map[string]interface{}{"mapping_id": chi.URLParam(r, "id"), "operation_id": opID})
	writeJSON(w, http.StatusAccepted, map[string]interface{}{"operation_id": opID, "status": "pending"})
}

func (a *API) toggleMapping(w http.ResponseWriter, r *http.Request) {
	if mustChange(w, r, authFrom(r)) {
		return
	}
	var input struct {
		Enabled               bool   `json:"enabled"`
		ExpectedConfigVersion *int64 `json:"expected_config_version"`
		ExpectedRevision      *int64 `json:"expected_revision"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if err := a.App.ToggleMapping(r.Context(), authFrom(r), chi.URLParam(r, "id"), input.Enabled, service.ToggleMappingOptions{ExpectedConfigVersion: input.ExpectedConfigVersion, ExpectedRevision: input.ExpectedRevision, IdempotencyKey: r.Header.Get("Idempotency-Key")}); err != nil {
		a.mappingProblem(w, r, err)
		return
	}
	a.notifyConfigChanged(authFrom(r).UserID, "mapping", chi.URLParam(r, "id"))
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

func (a *API) listDomains(w http.ResponseWriter, r *http.Request) {
	items, err := a.App.ListDomains(r.Context(), authFrom(r).UserID)
	if err != nil {
		problem(w, r, 500, "DOMAINS_READ_FAILED", "无法读取域名绑定。", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items})
}

func (a *API) createDomain(w http.ResponseWriter, r *http.Request) {
	if mustChange(w, r, authFrom(r)) {
		return
	}
	var input service.DomainRequest
	if !decodeJSON(w, r, &input) {
		return
	}
	item, err := a.App.CreateDomain(r.Context(), authFrom(r), input, r.Header.Get("Idempotency-Key"))
	if err != nil {
		a.mappingProblem(w, r, err)
		return
	}
	a.notifyConfigChanged(authFrom(r).UserID, "domain", item.ID)
	writeJSON(w, http.StatusAccepted, item)
}

func (a *API) deleteDomain(w http.ResponseWriter, r *http.Request) {
	if mustChange(w, r, authFrom(r)) {
		return
	}
	opID, err := a.App.DeleteDomain(r.Context(), authFrom(r), chi.URLParam(r, "id"), r.Header.Get("Idempotency-Key"))
	if err != nil {
		a.mappingProblem(w, r, err)
		return
	}
	a.notifyConfigChanged(authFrom(r).UserID, "domain", chi.URLParam(r, "id"))
	writeJSON(w, http.StatusAccepted, map[string]interface{}{"operation_id": opID, "status": "pending"})
}

func (a *API) domainDNSAction(w http.ResponseWriter, r *http.Request) {
	if mustChange(w, r, authFrom(r)) {
		return
	}
	var input struct {
		Action string `json:"action"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if err := a.App.ResolveDomainDNS(r.Context(), authFrom(r), chi.URLParam(r, "id"), input.Action, r.Header.Get("Idempotency-Key")); err != nil {
		a.mappingProblem(w, r, err)
		return
	}
	a.notifyConfigChanged(authFrom(r).UserID, "domain", chi.URLParam(r, "id"))
	writeJSON(w, http.StatusAccepted, map[string]interface{}{"status": "pending", "action": input.Action})
}

func (a *API) fullConfig(w http.ResponseWriter, r *http.Request) {
	if authFrom(r).Role != "user" {
		problem(w, r, 404, "FORBIDDEN", "资源不存在。", service.ErrForbidden)
		return
	}
	if authFrom(r).MustChange {
		problem(w, r, 403, "AUTH_PASSWORD_CHANGE_REQUIRED", "首次登录必须先修改密码。", service.ErrForbidden)
		return
	}
	snapshot, err := a.App.FullConfig(r.Context(), authFrom(r))
	if err != nil {
		problem(w, r, 500, "CONFIG_READ_FAILED", "无法生成配置快照。", err)
		return
	}
	writeJSON(w, http.StatusOK, snapshot)
}

func (a *API) signingKey(w http.ResponseWriter, r *http.Request) {
	if authFrom(r).Role != "user" {
		problem(w, r, 404, "FORBIDDEN", "资源不存在。", service.ErrForbidden)
		return
	}
	pub := a.App.Crypto.SignKey.Public().(ed25519.PublicKey)
	writeJSON(w, http.StatusOK, map[string]interface{}{"key_id": a.App.Crypto.KeyID, "algorithm": "Ed25519", "public_key": hex.EncodeToString(pub)})
}

func (a *API) applyResult(w http.ResponseWriter, r *http.Request) {
	if authFrom(r).Role != "user" {
		problem(w, r, 404, "FORBIDDEN", "资源不存在。", service.ErrForbidden)
		return
	}
	var input service.ApplyResultRequest
	if !decodeJSON(w, r, &input) {
		return
	}
	if err := a.App.ApplyResult(r.Context(), authFrom(r), input); err != nil {
		status, code, detail := http.StatusBadRequest, "CONFIG_APPLY_FAILED", "配置应用结果未能写入。"
		if errors.Is(err, service.ErrConfigConflict) {
			status, code, detail = http.StatusConflict, "CONFIG_VERSION_CONFLICT", "配置版本已变化，旧应用结果被拒绝。"
		}
		problem(w, r, status, code, detail, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "request_id": requestID(r)})
}

func (a *API) heartbeat(w http.ResponseWriter, r *http.Request) {
	if authFrom(r).Role != "user" {
		problem(w, r, 404, "FORBIDDEN", "资源不存在。", service.ErrForbidden)
		return
	}
	var input struct {
		ClientPanelVersion string `json:"client_panel_version"`
		FRPCVersion        string `json:"frpc_version"`
	}
	_ = decodeJSON(w, r, &input)
	if err := a.App.Heartbeat(r.Context(), authFrom(r), input.ClientPanelVersion, input.FRPCVersion); err != nil {
		problem(w, r, 500, "HEARTBEAT_FAILED", "心跳写入失败。", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "server_time": time.Now().UTC()})
}

func (a *API) operations(w http.ResponseWriter, r *http.Request) {
	items, err := a.App.Operations(r.Context(), authFrom(r).UserID, authFrom(r).Role == "admin")
	if err != nil {
		problem(w, r, 500, "OPERATIONS_READ_FAILED", "无法读取操作记录。", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items})
}

func (a *API) retryOperation(w http.ResponseWriter, r *http.Request) {
	if mustChange(w, r, authFrom(r)) {
		return
	}
	if err := a.App.RetryOperation(r.Context(), authFrom(r), chi.URLParam(r, "id")); err != nil {
		a.mappingProblem(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]interface{}{"status": "pending", "operation_id": chi.URLParam(r, "id")})
}

func (a *API) cloudflareStatus(w http.ResponseWriter, r *http.Request) {
	status, err := a.App.CloudflareStatus(r.Context(), authFrom(r).UserID)
	if err != nil {
		problem(w, r, 500, "CLOUDFLARE_STATUS_FAILED", "无法读取 Cloudflare Token 状态。", err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (a *API) cloudflareToken(w http.ResponseWriter, r *http.Request) {
	if mustChange(w, r, authFrom(r)) {
		return
	}
	var input struct {
		Token        string `json:"token"`
		ReauthTicket string `json:"reauth_ticket"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if !a.requireReauthTicket(w, r, input.ReauthTicket) {
		return
	}
	if err := a.App.SaveCloudflareToken(r.Context(), authFrom(r), input.Token, input.ReauthTicket); err != nil {
		status, code, detail := http.StatusBadRequest, "CLOUDFLARE_TOKEN_INVALID", "Cloudflare Token 未通过本地格式校验，当前 active Token 不变。"
		if errors.Is(err, service.ErrReauthRequired) || errors.Is(err, service.ErrInvalidCredentials) {
			status, code, detail = http.StatusUnauthorized, "AUTH_REAUTH_REQUIRED", "敏感操作需要先完成二次认证。"
		}
		problem(w, r, status, code, detail, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]interface{}{"status": "pending", "message": "Token 已加密保存，等待权限验证。"})
}

func (a *API) clearCloudflare(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ReauthTicket string `json:"reauth_ticket"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if !a.requireReauthTicket(w, r, input.ReauthTicket) {
		return
	}
	if err := a.App.ClearCloudflareToken(r.Context(), authFrom(r), input.ReauthTicket); err != nil {
		status, code, detail := http.StatusInternalServerError, "CLOUDFLARE_TOKEN_CLEAR_FAILED", "清除 Cloudflare Token 失败。"
		if errors.Is(err, service.ErrInvalidCredentials) {
			status, code, detail = http.StatusUnauthorized, "AUTH_INVALID_CREDENTIALS", "当前管理员密码不正确。"
		} else if errors.Is(err, service.ErrReauthRequired) {
			status, code, detail = http.StatusUnauthorized, "AUTH_REAUTH_REQUIRED", "敏感操作需要先完成二次认证。"
		}
		problem(w, r, status, code, detail, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "missing", "message": "Token 已清除；已有 DNS 记录不会被自动删除。"})
}

func (a *API) adminUsers(w http.ResponseWriter, r *http.Request) {
	users, err := a.App.AdminUsers(r.Context())
	if err != nil {
		problem(w, r, 500, "USERS_READ_FAILED", "无法读取用户。", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": users})
}

func (a *API) createUser(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Username     string `json:"username"`
		ReauthTicket string `json:"reauth_ticket"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if !a.requireReauthTicket(w, r, input.ReauthTicket) {
		return
	}
	user, password, err := a.App.CreateUser(r.Context(), authFrom(r), input.Username)
	if err != nil {
		problem(w, r, 400, "USER_CREATE_FAILED", "用户创建失败。", err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"user": user, "initial_password": password, "warning": "只展示一次，请通过受保护渠道交付。"})
}

func (a *API) deleteUser(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ReauthTicket string `json:"reauth_ticket"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if !a.requireReauthTicket(w, r, input.ReauthTicket) {
		return
	}
	force := r.URL.Query().Get("force") == "true"
	opID, err := a.App.DeleteUser(r.Context(), authFrom(r), chi.URLParam(r, "id"), force, r.Header.Get("Idempotency-Key"))
	if err != nil {
		a.mappingProblem(w, r, err)
		return
	}
	a.notifyUser(chi.URLParam(r, "id"), "user_disabled", map[string]interface{}{"reason": "user_delete_requested"})
	a.notifyUser(chi.URLParam(r, "id"), "shutdown_frpc", map[string]interface{}{"reason": "user_delete_requested"})
	writeJSON(w, http.StatusAccepted, map[string]interface{}{"operation_id": opID, "status": "pending", "force": force})
}

func (a *API) setUserStatus(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Status       string `json:"status"`
		ReauthTicket string `json:"reauth_ticket"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if !a.requireReauthTicket(w, r, input.ReauthTicket) {
		return
	}
	if err := a.App.SetUserStatus(r.Context(), authFrom(r), chi.URLParam(r, "id"), input.Status); err != nil {
		a.mappingProblem(w, r, err)
		return
	}
	if input.Status == "disabled" {
		a.notifyUser(chi.URLParam(r, "id"), "user_disabled", map[string]interface{}{"reason": "admin_action"})
	} else {
		a.notifyUser(chi.URLParam(r, "id"), "force_full_sync", map[string]interface{}{"reason": "user_reactivated"})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}
func (a *API) resetPassword(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ReauthTicket string `json:"reauth_ticket"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if !a.requireReauthTicket(w, r, input.ReauthTicket) {
		return
	}
	password, err := a.App.ResetUserPassword(r.Context(), authFrom(r), chi.URLParam(r, "id"))
	if err != nil {
		a.mappingProblem(w, r, err)
		return
	}
	a.notifyUser(chi.URLParam(r, "id"), "session_replaced", map[string]interface{}{"reason": "password_reset"})
	writeJSON(w, http.StatusOK, map[string]interface{}{"initial_password": password, "warning": "只展示一次，请通过受保护渠道交付。"})
}

func (a *API) adminResetFRPCredential(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ReauthTicket string `json:"reauth_ticket"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if !a.requireReauthTicket(w, r, input.ReauthTicket) {
		return
	}
	userID := chi.URLParam(r, "id")
	result, err := a.App.ResetFRPCredential(r.Context(), authFrom(r), userID, input.ReauthTicket, r.Header.Get("Idempotency-Key"))
	if err != nil {
		a.frpResetProblem(w, r, err)
		return
	}
	a.notifyUser(userID, "frp_secret_rotated", map[string]interface{}{"secret_version": result.SecretVersion, "session_generation": result.SessionGeneration})
	a.notifyUser(userID, "shutdown_frpc", map[string]interface{}{"reason": "frp_secret_rotated"})
	writeJSON(w, http.StatusOK, result)
}

func (a *API) requireReauthTicket(w http.ResponseWriter, r *http.Request, ticket string) bool {
	if err := a.App.RequireReauthTicket(r.Context(), authFrom(r), ticket); err != nil {
		problem(w, r, http.StatusUnauthorized, "AUTH_REAUTH_REQUIRED", "敏感操作需要先完成二次认证。", err)
		return false
	}
	return true
}

func (a *API) frpResetProblem(w http.ResponseWriter, r *http.Request, err error) {
	status, code, detail := http.StatusBadRequest, "FRP_SECRET_RESET_FAILED", "FRP 凭证重置失败。"
	switch {
	case errors.Is(err, service.ErrInvalidCredentials):
		status, code, detail = http.StatusUnauthorized, "AUTH_INVALID_CREDENTIALS", "当前密码不正确。"
	case errors.Is(err, service.ErrReauthRequired):
		status, code, detail = http.StatusUnauthorized, "AUTH_REAUTH_REQUIRED", "敏感操作需要先完成二次认证。"
	case errors.Is(err, service.ErrForbidden):
		status, code, detail = http.StatusForbidden, "FORBIDDEN", "没有权限重置该 FRP 凭证。"
	case errors.Is(err, service.ErrIdempotencyReuse):
		status, code, detail = http.StatusConflict, "IDEMPOTENCY_KEY_REUSED", "幂等键已用于不同的 FRP 凭证重置请求。"
	case errors.Is(err, service.ErrNotFound):
		status, code, detail = http.StatusNotFound, "NOT_FOUND", "目标用户不存在。"
	}
	problem(w, r, status, code, detail, err)
}
func (a *API) adminOperations(w http.ResponseWriter, r *http.Request) { a.operations(w, r) }

func (a *API) adminStats(w http.ResponseWriter, r *http.Request) {
	var users, mappings, pending, errorsCount int
	_ = a.App.DB.QueryRowContext(r.Context(), `SELECT COUNT(1) FROM users WHERE role='user' AND status='active'`).Scan(&users)
	_ = a.App.DB.QueryRowContext(r.Context(), `SELECT COUNT(1) FROM mappings WHERE lifecycle_status <> 'deleted'`).Scan(&mappings)
	_ = a.App.DB.QueryRowContext(r.Context(), `SELECT COUNT(1) FROM mappings WHERE lifecycle_status IN ('reserved','pending_apply')`).Scan(&pending)
	_ = a.App.DB.QueryRowContext(r.Context(), `SELECT COUNT(1) FROM mappings WHERE lifecycle_status='config_error'`).Scan(&errorsCount)
	writeJSON(w, http.StatusOK, map[string]interface{}{"active_users": users, "mappings": mappings, "pending": pending, "errors": errorsCount, "server_uptime_seconds": int(time.Since(a.App.Started).Seconds()), "frps_public_host": a.App.Config.FRPSPublicHost, "frps_public_port": a.App.Config.FRPSPublicPort})
}

func (a *API) routerStatus(w http.ResponseWriter, r *http.Request) {
	status, err := a.App.RouterStatus(r.Context())
	if err != nil {
		problem(w, r, 500, "ROUTER_STATUS_FAILED", "无法读取 Router Snapshot 状态。", err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (a *API) routerRebuild(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ReauthTicket string `json:"reauth_ticket"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if !a.requireReauthTicket(w, r, input.ReauthTicket) {
		return
	}
	if err := a.App.EnqueueRouterSnapshot(r.Context()); err != nil {
		problem(w, r, 500, "ROUTER_REBUILD_FAILED", "Router Snapshot 任务无法入队。", err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]interface{}{"status": "pending", "message": "Router Snapshot rebuild queued."})
}

func (a *API) createBackup(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Password     string `json:"password"`
		ReauthTicket string `json:"reauth_ticket"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if !a.requireReauthTicket(w, r, input.ReauthTicket) {
		return
	}
	path := fmt.Sprintf("%s/backups/backup-%s.fppb", a.App.Config.DataDir, time.Now().UTC().Format("20060102T150405Z"))
	if err := backup.CreateWithOptions(r.Context(), a.App.DB.DB, path, input.Password, backup.Options{DataDir: a.App.Config.DataDir}); err != nil {
		problem(w, r, 400, "BACKUP_FAILED", "加密备份创建失败。", err)
		return
	}
	_ = a.App.Audit(r.Context(), authFrom(r), "backup_created", "backup", path, "success", nil, "")
	writeJSON(w, http.StatusCreated, map[string]interface{}{"status": "succeeded", "file": "backups/" + path[strings.LastIndex(path, "/backups/")+9:]})
}

func (a *API) websocket(w http.ResponseWriter, r *http.Request) {
	requestedVersion := strings.TrimSpace(r.Header.Get("X-FRP-Protocol-Version"))
	if requestedVersion == "" {
		requestedVersion = strings.TrimSpace(r.URL.Query().Get("protocol_version"))
	}
	if requestedVersion != "" && requestedVersion != "v1" {
		w.Header().Set("Upgrade-Required", "v1")
		problem(w, r, http.StatusUpgradeRequired, "UPGRADE_REQUIRED", "WebSocket protocol version is unsupported; use v1.", nil)
		return
	}
	ac := authFrom(r)
	conn, err := a.WS.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	conn.SetReadLimit(64 << 10)
	a.mu.Lock()
	if a.clients[ac.UserID] == nil {
		a.clients[ac.UserID] = map[*websocket.Conn]struct{}{}
	}
	a.clients[ac.UserID][conn] = struct{}{}
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		delete(a.clients[ac.UserID], conn)
		if len(a.clients[ac.UserID]) == 0 {
			delete(a.clients, ac.UserID)
		}
		a.mu.Unlock()
		_ = conn.Close()
	}()
	_ = a.writeWS(conn, wsEnvelope{Type: "connected", Payload: map[string]interface{}{"user_id": ac.UserID}})
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		var message wsEnvelope
		if json.Unmarshal(data, &message) == nil && message.ProtocolVersion != "v1" {
			_ = a.writeWS(conn, wsEnvelope{Type: "protocol_error", Payload: map[string]interface{}{"code": "UPGRADE_REQUIRED", "minimum_protocol_version": "v1"}})
			return
		}
		if message.Type == "heartbeat" {
			if err := a.App.TouchSession(r.Context(), ac); err != nil {
				_ = a.writeWS(conn, wsEnvelope{Type: "session_expired", Payload: map[string]interface{}{"reason": "session_no_longer_valid"}})
				return
			}
			_ = a.writeWS(conn, wsEnvelope{Type: "heartbeat_ack", Payload: map[string]interface{}{"server_time": time.Now().UTC()}})
		}
	}
}

func (a *API) writeWS(conn *websocket.Conn, message wsEnvelope) error {
	message.MessageID = shortID()
	message.ProtocolVersion = "v1"
	message.Timestamp = time.Now().UTC()
	a.mu.Lock()
	defer a.mu.Unlock()
	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return conn.WriteJSON(message)
}

func (a *API) notifyUser(userID, messageType string, payload interface{}) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for conn := range a.clients[userID] {
		message := wsEnvelope{MessageID: shortID(), ProtocolVersion: "v1", Timestamp: time.Now().UTC(), Type: messageType, Payload: payload}
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if err := conn.WriteJSON(message); err != nil {
			delete(a.clients[userID], conn)
			_ = conn.Close()
		}
	}
}

func (a *API) notifyConfigChanged(userID, resourceType, resourceID string) {
	a.notifyUser(userID, "config_version_changed", map[string]interface{}{
		"resource_type":   resourceType,
		"resource_id":     resourceID,
		"force_full_sync": true,
	})
}

func (a *API) frpPlugin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		problem(w, r, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "FRP 插件接口只接受 POST。", nil)
		return
	}
	operation := strings.TrimSpace(r.URL.Query().Get("op"))
	if operation != "" {
		a.frpPluginRPC(w, r, operation)
		return
	}
	// Keep the pre-v3 flat request shape readable for older development tools.
	// Real frps requests use the versioned ?op=... envelope handled above.
	var input struct {
		Operation         string `json:"operation"`
		Username          string `json:"frp_username"`
		RuntimeCredential string `json:"runtime_credential"`
		SessionGeneration int64  `json:"session_generation"`
		MappingID         string `json:"mapping_id"`
		MappingRevision   int64  `json:"mapping_revision"`
		RemotePort        int    `json:"remote_port"`
		Hostname          string `json:"hostname"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	ok, code, detail := a.App.AuthorizeFRP(r.Context(), input.Operation, input.Username, input.RuntimeCredential, input.SessionGeneration, input.MappingID, input.MappingRevision, input.RemotePort, input.Hostname)
	if !ok {
		problem(w, r, http.StatusForbidden, code, detail, service.ErrForbidden)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"allowed": true})
}

type frpPluginEnvelope struct {
	Version   string          `json:"version,omitempty"`
	Operation string          `json:"op,omitempty"`
	Content   json.RawMessage `json:"content"`
}

type frpPluginResponse struct {
	Reject       bool        `json:"reject"`
	RejectReason string      `json:"reject_reason,omitempty"`
	Unchange     bool        `json:"unchange,omitempty"`
	Content      interface{} `json:"content,omitempty"`
}

// frpPluginRPC implements the public frps HTTP server-plugin protocol. The
// plugin is intentionally a narrow authorization boundary: it never mutates
// the request content and every operation re-validates the opaque runtime
// credential and session generation before allowing frps to proceed.
func (a *API) frpPluginRPC(w http.ResponseWriter, r *http.Request, operation string) {
	if version := strings.TrimSpace(r.URL.Query().Get("version")); version != "" && version != "0.1.0" {
		problem(w, r, http.StatusBadRequest, "FRP_PLUGIN_VERSION_UNSUPPORTED", "FRP 插件协议版本不受支持。", nil)
		return
	}
	var envelope frpPluginEnvelope
	if !decodeJSON(w, r, &envelope) {
		return
	}
	if len(envelope.Content) == 0 || string(envelope.Content) == "null" {
		problem(w, r, http.StatusBadRequest, "FRP_PLUGIN_CONTENT_REQUIRED", "FRP 插件请求缺少 content。", nil)
		return
	}
	var content map[string]interface{}
	if err := json.Unmarshal(envelope.Content, &content); err != nil || content == nil {
		problem(w, r, http.StatusBadRequest, "FRP_PLUGIN_CONTENT_INVALID", "FRP 插件 content 必须是 JSON 对象。", err)
		return
	}
	if operation == "Login" && !frpVersionAtLeast(frpPluginString(content["version"]), "0.68.0") {
		writeJSON(w, http.StatusOK, frpPluginReject("FRP_VERSION_UNSUPPORTED", "FRPC 版本低于平台要求。"))
		return
	}

	username, metas := frpPluginIdentity(operation, content)
	runtimeCredential := strings.TrimSpace(metas["frp_runtime_credential"])
	userFRPSecret := strings.TrimSpace(metas["frp_user_secret"])
	generation, generationOK := parseFRPGeneration(metas["session_generation"])
	if username == "" || runtimeCredential == "" || userFRPSecret == "" || !generationOK {
		writeJSON(w, http.StatusOK, frpPluginReject("FRP_AUTHENTICATION_REQUIRED", "FRP 身份或运行时会话元数据缺失。"))
		return
	}

	if operation == "NewProxy" {
		mappingMetas := frpPluginStringMap(content["metas"])
		mappingID := strings.TrimSpace(mappingMetas["mapping_id"])
		mappingRevision, revisionOK := parseFRPGeneration(mappingMetas["mapping_revision"])
		if mappingID == "" || !revisionOK {
			writeJSON(w, http.StatusOK, frpPluginReject("FRP_MAPPING_METADATA_REQUIRED", "FRP 代理缺少 mapping_id 或 mapping_revision。"))
			return
		}
		proxyName := strings.TrimSpace(frpPluginString(content["proxy_name"]))
		expectedProxyName := "mapping-" + mappingID
		if proxyName != expectedProxyName && proxyName != username+"."+expectedProxyName {
			writeJSON(w, http.StatusOK, frpPluginReject("PROXY_NAME_NOT_ALLOWED", "代理名称不是平台生成的 Mapping 名称。"))
			return
		}
		remotePort := parseFRPInt(content["remote_port"])
		proxyType := strings.ToLower(strings.TrimSpace(frpPluginString(content["proxy_type"])))
		if proxyType == "" {
			writeJSON(w, http.StatusOK, frpPluginReject("FRP_PROXY_TYPE_REQUIRED", "FRP 代理缺少 proxy_type。"))
			return
		}
		hostnames := frpPluginStrings(content["custom_domains"])
		if (proxyType == "tcp" || proxyType == "udp") && len(hostnames) > 0 {
			writeJSON(w, http.StatusOK, frpPluginReject("PROXY_DOMAINS_NOT_ALLOWED", "TCP/UDP 代理不能携带业务域名。"))
			return
		}
		if len(hostnames) == 0 {
			hostnames = []string{""}
		}
		for _, hostname := range hostnames {
			if ok, code, detail := a.App.AuthorizeFRPWithCredentials(r.Context(), operation, username, runtimeCredential, userFRPSecret, generation, mappingID, mappingRevision, remotePort, hostname, proxyType); !ok {
				writeJSON(w, http.StatusOK, frpPluginReject(code, detail))
				return
			}
		}
		writeJSON(w, http.StatusOK, frpPluginAllow())
		return
	}

	ok, code, detail := a.App.AuthorizeFRPWithCredentials(r.Context(), operation, username, runtimeCredential, userFRPSecret, generation, "", 0, 0, "", "")
	if !ok {
		writeJSON(w, http.StatusOK, frpPluginReject(code, detail))
		return
	}
	writeJSON(w, http.StatusOK, frpPluginAllow())
}

func frpPluginIdentity(operation string, content map[string]interface{}) (string, map[string]string) {
	if operation == "Login" {
		return strings.TrimSpace(frpPluginString(content["user"])), frpPluginStringMap(content["metas"])
	}
	user := frpPluginMap(content["user"])
	return strings.TrimSpace(frpPluginString(user["user"])), frpPluginStringMap(user["metas"])
}

func frpPluginMap(value interface{}) map[string]interface{} {
	if object, ok := value.(map[string]interface{}); ok {
		return object
	}
	return nil
}

func frpPluginStringMap(value interface{}) map[string]string {
	result := make(map[string]string)
	for key, raw := range frpPluginMap(value) {
		if stringValue := strings.TrimSpace(frpPluginString(raw)); stringValue != "" {
			result[key] = stringValue
		}
	}
	return result
}

func frpPluginString(value interface{}) string {
	switch value := value.(type) {
	case string:
		return value
	case json.Number:
		return value.String()
	case float64:
		if value == float64(int64(value)) {
			return strconv.FormatInt(int64(value), 10)
		}
	}
	return ""
}

func frpPluginStrings(value interface{}) []string {
	items, ok := value.([]interface{})
	if !ok {
		return nil
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		if value := strings.TrimSpace(frpPluginString(item)); value != "" {
			result = append(result, value)
		}
	}
	return result
}

func parseFRPGeneration(value interface{}) (int64, bool) {
	parsed := strings.TrimSpace(frpPluginString(value))
	if parsed == "" {
		return 0, false
	}
	generation, err := strconv.ParseInt(parsed, 10, 64)
	return generation, err == nil && generation > 0
}

func parseFRPInt(value interface{}) int {
	switch value := value.(type) {
	case float64:
		return int(value)
	case json.Number:
		parsed, _ := strconv.Atoi(value.String())
		return parsed
	case string:
		parsed, _ := strconv.Atoi(value)
		return parsed
	}
	return 0
}

func frpVersionAtLeast(actual, minimum string) bool {
	parse := func(value string) ([3]int, bool) {
		var result [3]int
		parts := strings.Split(strings.TrimSpace(value), ".")
		if len(parts) < 2 {
			return result, false
		}
		for index := 0; index < len(result) && index < len(parts); index++ {
			part := parts[index]
			for offset, character := range part {
				if character < '0' || character > '9' {
					part = part[:offset]
					break
				}
			}
			if part == "" {
				return result, false
			}
			parsed, err := strconv.Atoi(part)
			if err != nil {
				return result, false
			}
			result[index] = parsed
		}
		return result, true
	}
	actualVersion, actualOK := parse(actual)
	minimumVersion, minimumOK := parse(minimum)
	if !actualOK || !minimumOK {
		return false
	}
	for index := range actualVersion {
		if actualVersion[index] != minimumVersion[index] {
			return actualVersion[index] > minimumVersion[index]
		}
	}
	return true
}

func frpPluginAllow() frpPluginResponse {
	return frpPluginResponse{Unchange: true}
}

func frpPluginReject(code, detail string) frpPluginResponse {
	reason := strings.TrimSpace(code)
	if detail != "" {
		reason += ": " + strings.TrimSpace(detail)
	}
	return frpPluginResponse{Reject: true, RejectReason: reason}
}

func (a *API) mappingProblem(w http.ResponseWriter, r *http.Request, err error) {
	status := 400
	code := "VALIDATION_FAILED"
	detail := "请求未通过校验。"
	switch {
	case strings.Contains(err.Error(), "quota exceeded"):
		status = http.StatusTooManyRequests
		code = "QUOTA_EXCEEDED"
		detail = "当前资源或待处理任务已达到配额，请等待现有任务完成或联系管理员。"
	case errors.Is(err, service.ErrNotFound):
		status = 404
		code = "NOT_FOUND"
		detail = "资源不存在。"
	case errors.Is(err, service.ErrPortReserved):
		status = 409
		code = "PORT_ALREADY_RESERVED"
		detail = "远程端口已被占用。"
	case errors.Is(err, service.ErrConfigConflict):
		status = 409
		code = "CONFIG_VERSION_CONFLICT"
		detail = "配置已发生变化，请刷新后重试。"
	case errors.Is(err, service.ErrRevisionConflict):
		status = 409
		code = "RESOURCE_REVISION_CONFLICT"
		detail = "资源 Revision 已发生变化，请刷新后重试。"
	case errors.Is(err, service.ErrIdempotencyReuse):
		status = 409
		code = "IDEMPOTENCY_KEY_REUSED"
		detail = "幂等键已用于不同请求。"
	case errors.Is(err, service.ErrForbidden):
		status = 403
		code = "FORBIDDEN"
		detail = "没有访问权限。"
	}
	problem(w, r, status, code, detail, err)
}

func mustChange(w http.ResponseWriter, r *http.Request, ac service.AuthContext) bool {
	if ac.MustChange && r.URL.Path != "/api/v1/auth/change-password" {
		problem(w, r, http.StatusForbidden, "AUTH_PASSWORD_CHANGE_REQUIRED", "首次登录必须先修改密码。", service.ErrForbidden)
		return true
	}
	return false
}

func authFrom(r *http.Request) service.AuthContext {
	value, _ := r.Context().Value(authContextKey).(service.AuthContext)
	return value
}
func requestID(r *http.Request) string {
	value, _ := r.Context().Value(requestIDKey).(string)
	return value
}
func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}
func shortID() string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	return hex.EncodeToString(sum[:8])
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target interface{}) bool {
	if r.Body == nil {
		problem(w, r, 400, "INVALID_JSON", "请求体不能为空。", nil)
		return false
	}
	defer r.Body.Close()
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		problem(w, r, 400, "INVALID_JSON", "请求格式不正确。", err)
		return false
	}
	var extra interface{}
	if err := decoder.Decode(&extra); err != io.EOF {
		problem(w, r, 400, "INVALID_JSON", "请求体只能包含一个 JSON 值。", err)
		return false
	}
	return true
}
func writeJSON(w http.ResponseWriter, status int, value interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

type problemDetail struct {
	Type      string `json:"type"`
	Title     string `json:"title"`
	Status    int    `json:"status"`
	Detail    string `json:"detail"`
	Instance  string `json:"instance"`
	Code      string `json:"code"`
	RequestID string `json:"request_id"`
}

func problem(w http.ResponseWriter, r *http.Request, status int, code, detail string, err error) {
	if w == nil {
		return
	}
	if status >= 500 {
		detail = "服务暂时不可用，请稍后重试。"
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(problemDetail{Type: "https://docs.example.invalid/problems/" + strings.ToLower(strings.ReplaceAll(code, "_", "-")), Title: code, Status: status, Detail: detail, Instance: r.URL.Path, Code: code, RequestID: requestID(r)})
	_ = err
}
