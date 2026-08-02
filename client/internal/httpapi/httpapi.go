package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/ricardo/frp-panel-platform/client/internal/app"
	"github.com/ricardo/frp-panel-platform/client/internal/id"
)

type contextKey string

const requestIDKey contextKey = "request_id"

type API struct {
	App         *app.App
	apiLimit    *requestRateLimiter
	loginLimit  *requestRateLimiter
	concurrency chan struct{}
}

func New(a *app.App) *API {
	return &API{App: a, apiLimit: newRequestRateLimiter(300, time.Minute), loginLimit: newRequestRateLimiter(10, time.Minute), concurrency: make(chan struct{}, 64)}
}

func (a *API) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(a.headers, a.requestID, a.protocolV1, a.cors, a.rateLimit, a.concurrencyLimit, a.localAuth)
	r.Get("/healthz", a.health)
	r.Get("/", a.app)
	r.Handle("/assets/*", http.StripPrefix("/assets/", http.FileServer(http.Dir(filepath.Join(a.webDir(), "assets")))))
	r.Get("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join(a.webDir(), "favicon.svg"))
	})
	r.Handle("/favicon.svg", http.FileServer(http.Dir(a.webDir())))
	r.Post("/api/v1/login", a.login)
	r.Post("/api/v1/server/inspect", a.inspectServer)
	r.Group(func(r chi.Router) {
		r.Use(a.sessionRequired)
		r.Post("/api/v1/logout", a.logout)
		r.Post("/api/v1/password", a.password)
		r.Post("/api/v1/reauth", a.reauth)
		r.Post("/api/v1/frp-credential/reset", a.resetFRPCredential)
		r.Get("/api/v1/session", a.session)
		r.Get("/api/v1/dashboard", a.dashboard)
		r.Get("/api/v1/mappings", a.mappings)
		r.Post("/api/v1/mappings", a.createMapping)
		r.Put("/api/v1/mappings/{id}", a.updateMapping)
		r.Delete("/api/v1/mappings/{id}", a.deleteMapping)
		r.Post("/api/v1/mappings/{id}/toggle", a.toggleMapping)
		r.Get("/api/v1/domains", a.domains)
		r.Get("/api/v1/operations", a.operations)
		r.Post("/api/v1/domains", a.createDomain)
		r.Delete("/api/v1/domains/{id}", a.deleteDomain)
		r.Post("/api/v1/domains/{id}/dns-action", a.domainDNSAction)
		r.Get("/api/v1/config", a.config)
		r.Post("/api/v1/sync", a.sync)
		r.Get("/api/v1/local-status", a.localStatus)
		r.Get("/api/v1/logs", a.logs)
	})
	return r
}

func (a *API) requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := strings.TrimSpace(r.Header.Get("X-Request-ID"))
		if value == "" || len(value) > 80 || strings.ContainsAny(value, "\r\n") {
			value = id.New()
		}
		w.Header().Set("X-Request-ID", value)
		ctx := context.WithValue(r.Context(), requestIDKey, value)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (a *API) protocolV1(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requested := strings.TrimSpace(r.Header.Get("X-FRP-Protocol-Version")); requested != "" && requested != "v1" {
			w.Header().Set("Upgrade-Required", "v1")
			problem(w, r, http.StatusUpgradeRequired, "UPGRADE_REQUIRED", "Client Panel API protocol version is unsupported.")
			return
		}
		next.ServeHTTP(w, r)
	})
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
				problem(w, r, http.StatusTooManyRequests, "RATE_LIMITED", "请求过于频繁，请稍后重试。")
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
			problem(w, r, http.StatusTooManyRequests, "CONCURRENCY_LIMITED", "并发请求已达到上限，请稍后重试。")
		}
	})
}

func (a *API) headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self' http://127.0.0.1:5174 http://localhost:5174; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
func (a *API) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin == "http://127.0.0.1:5174" || origin == "http://localhost:5174" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Idempotency-Key, X-CSRF-Token, X-FRP-Protocol-Version")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
func (a *API) localAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !cidrAllowed(r.RemoteAddr, a.App.Config.AllowedCIDRs) {
			problem(w, r, http.StatusNotFound, "NOT_FOUND", "资源不存在。")
			return
		}
		if !hostAllowed(r.Host, a.App.Config.AllowedHost) {
			problem(w, r, http.StatusNotFound, "NOT_FOUND", "资源不存在。")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func cidrAllowed(remoteAddr string, configured []string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddr))
	if err != nil {
		host = strings.Trim(strings.TrimSpace(remoteAddr), "[]")
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, raw := range configured {
		_, network, err := net.ParseCIDR(strings.TrimSpace(raw))
		if err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}
func (a *API) sessionRequired(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("frp_client_session")
		if err != nil || !a.App.ValidateLocal(cookie.Value) {
			problem(w, r, 401, "SESSION_EXPIRED", "本地浏览器会话已失效，请重新登录。")
			return
		}
		if r.Method != "GET" && r.URL.Path != "/api/v1/logout" && !a.App.CSRFValid(r.Header.Get("X-CSRF-Token")) {
			problem(w, r, 403, "CSRF_INVALID", "请求校验失败，请刷新面板。")
			return
		}
		next.ServeHTTP(w, r)
	})
}
func (a *API) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]interface{}{"status": "ok", "service": "frp-panel-client"})
}
func (a *API) app(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, filepath.Join(a.webDir(), "index.html"))
}

func (a *API) webDir() string {
	candidates := []string{a.App.Config.ClientWebDir, "web/client/dist", "../web/client/dist"}
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
	return "web/client/dist"
}

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ServerPanelURL string `json:"server_panel_url"`
		Username       string `json:"username"`
		Password       string `json:"password"`
		TrustedSPKI    string `json:"trusted_spki_sha256,omitempty"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	limitKey := remoteIP(r) + "|" + strings.TrimSpace(input.Username)
	if a.loginLimit != nil {
		if ok, retry := a.loginLimit.allow(limitKey, time.Now().UTC()); !ok {
			seconds := int(retry.Seconds())
			if seconds < 1 {
				seconds = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(seconds))
			problem(w, r, http.StatusTooManyRequests, "AUTH_RATE_LIMITED", "登录尝试过于频繁，请稍后重试。")
			return
		}
	}
	session, err := a.App.LoginWithTrust(r.Context(), input.ServerPanelURL, input.Username, input.Password, input.TrustedSPKI)
	if err != nil {
		status, code, detail := loginProblem(err)
		problem(w, r, status, code, detail)
		return
	}
	if a.loginLimit != nil {
		a.loginLimit.reset(limitKey)
	}
	http.SetCookie(w, &http.Cookie{Name: "frp_client_session", Value: a.App.SessionCookie(), Path: "/", HttpOnly: true, Secure: a.App.Config.Environment == "production", SameSite: http.SameSiteStrictMode, MaxAge: 1800}) // #nosec G124 -- Secure is mandatory in production; development is loopback HTTP
	writeJSON(w, 200, session)
}

func loginProblem(err error) (int, string, string) {
	var remote app.RemoteError
	if errors.As(err, &remote) {
		code := remote.Code
		if code == "" {
			code = "AUTH_INVALID_CREDENTIALS"
		}
		detail := "用户名或密码不正确，或账号已停用。"
		if code == "SERVER_TLS_VALIDATION_FAILED" {
			detail = "Server Panel TLS 验证失败；请先检查证书并确认 SPKI 指纹。"
		}
		return remote.Status, code, detail
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "url") || strings.Contains(message, "scheme") || strings.Contains(message, "host") {
		return http.StatusBadRequest, "SERVER_ADDRESS_INVALID", "Server Panel 地址无效。"
	}
	if strings.Contains(message, "certificate") || strings.Contains(message, "tls") || strings.Contains(message, "x509") || strings.Contains(message, "https") {
		return http.StatusBadRequest, "SERVER_TLS_VALIDATION_FAILED", "Server Panel TLS 验证失败；请先检查证书并确认 SPKI 指纹。"
	}
	return http.StatusUnauthorized, "AUTH_INVALID_CREDENTIALS", "用户名或密码不正确，或账号已停用。"
}

func (a *API) inspectServer(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ServerPanelURL string `json:"server_panel_url"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	certificate, err := a.App.InspectServerCertificate(r.Context(), input.ServerPanelURL)
	if err != nil {
		problem(w, r, http.StatusBadRequest, "SERVER_CERTIFICATE_INSPECTION_FAILED", "无法检查 Server Panel 证书；未发送登录密码。", err)
		return
	}
	writeJSON(w, http.StatusOK, certificate)
}
func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	_ = a.App.Logout(r.Context())
	http.SetCookie(w, &http.Cookie{Name: "frp_client_session", Value: "", Path: "/", HttpOnly: true, Secure: a.App.Config.Environment == "production", MaxAge: -1, SameSite: http.SameSiteStrictMode}) // #nosec G124 -- Secure is mandatory in production; development is loopback HTTP
	writeJSON(w, 200, map[string]interface{}{"ok": true})
}
func (a *API) password(w http.ResponseWriter, r *http.Request) {
	var input struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	var response interface{}
	if err := a.App.Proxy(r.Context(), "POST", "/api/v1/auth/change-password", input, r.Header.Get("X-CSRF-Token"), &response); err != nil {
		problem(w, r, 400, "PASSWORD_CHANGE_FAILED", err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"ok": true})
}

func (a *API) reauth(w http.ResponseWriter, r *http.Request) {
	var input struct {
		CurrentPassword string `json:"current_password"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	var response interface{}
	if err := a.App.Proxy(r.Context(), "POST", "/api/v1/auth/reauth", input, r.Header.Get("X-CSRF-Token"), &response); err != nil {
		problem(w, r, 401, "AUTH_REAUTH_FAILED", err.Error())
		return
	}
	writeJSON(w, 200, response)
}

func (a *API) resetFRPCredential(w http.ResponseWriter, r *http.Request) {
	var input struct {
		CurrentPassword string `json:"current_password,omitempty"`
		ReauthTicket    string `json:"reauth_ticket,omitempty"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	var output map[string]interface{}
	if input.ReauthTicket == "" && input.CurrentPassword != "" {
		var ticketResponse struct {
			ReauthTicket string `json:"reauth_ticket"`
		}
		if err := a.App.Proxy(r.Context(), "POST", "/api/v1/auth/reauth", map[string]string{"current_password": input.CurrentPassword}, r.Header.Get("X-CSRF-Token"), &ticketResponse); err != nil {
			problem(w, r, 401, "AUTH_REAUTH_FAILED", err.Error())
			return
		}
		input.CurrentPassword = ""
		input.ReauthTicket = ticketResponse.ReauthTicket
	}
	if err := a.App.Proxy(r.Context(), "POST", "/api/v1/auth/reset-frp-credential", input, r.Header.Get("X-CSRF-Token"), &output, r.Header.Get("Idempotency-Key")); err != nil {
		problem(w, r, 400, "FRP_SECRET_RESET_FAILED", err.Error(), err)
		return
	}
	// Server revokes the current session as part of the rotation. Clear the
	// local session and all runtime material immediately after the 200 response.
	_ = a.App.Logout(r.Context())
	http.SetCookie(w, &http.Cookie{Name: "frp_client_session", Value: "", Path: "/", HttpOnly: true, Secure: a.App.Config.Environment == "production", MaxAge: -1, SameSite: http.SameSiteStrictMode}) // #nosec G124 -- Secure is mandatory in production; development is loopback HTTP
	writeJSON(w, 200, output)
}
func (a *API) session(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, a.App.Session()) }
func (a *API) dashboard(w http.ResponseWriter, r *http.Request) {
	var output interface{}
	if err := a.App.Proxy(r.Context(), "GET", "/api/v1/dashboard", nil, "", &output); err != nil {
		problem(w, r, 503, "SERVER_UNAVAILABLE", "Server Panel 暂不可达，当前仅可查看本地缓存。", err)
		return
	}
	a.markDataSource(w)
	writeJSON(w, 200, output)
}
func (a *API) mappings(w http.ResponseWriter, r *http.Request) {
	var output interface{}
	if err := a.App.Proxy(r.Context(), "GET", "/api/v1/mappings", nil, "", &output); err != nil {
		problem(w, r, 503, "SERVER_UNAVAILABLE", "Server Panel 暂不可达。", err)
		return
	}
	a.markDataSource(w)
	writeJSON(w, 200, output)
}
func (a *API) createMapping(w http.ResponseWriter, r *http.Request) {
	var input map[string]interface{}
	if !decodeJSON(w, r, &input) {
		return
	}
	var output interface{}
	if err := a.App.Proxy(r.Context(), "POST", "/api/v1/mappings", input, r.Header.Get("X-CSRF-Token"), &output, r.Header.Get("Idempotency-Key")); err != nil {
		problem(w, r, 400, "MAPPING_CREATE_FAILED", err.Error(), err)
		return
	}
	_ = a.App.FetchConfigAndApply(r.Context())
	writeJSON(w, 201, output)
}
func (a *API) updateMapping(w http.ResponseWriter, r *http.Request) {
	var input map[string]interface{}
	if !decodeJSON(w, r, &input) {
		return
	}
	var output interface{}
	if err := a.App.Proxy(r.Context(), "PUT", "/api/v1/mappings/"+chi.URLParam(r, "id"), input, r.Header.Get("X-CSRF-Token"), &output, r.Header.Get("Idempotency-Key")); err != nil {
		problem(w, r, 400, "MAPPING_UPDATE_FAILED", err.Error(), err)
		return
	}
	_ = a.App.FetchConfigAndApply(r.Context())
	writeJSON(w, 200, output)
}
func (a *API) deleteMapping(w http.ResponseWriter, r *http.Request) {
	var output interface{}
	path := "/api/v1/mappings/" + chi.URLParam(r, "id")
	if err := a.App.Proxy(r.Context(), "DELETE", path, nil, r.Header.Get("X-CSRF-Token"), &output, r.Header.Get("Idempotency-Key")); err != nil {
		problem(w, r, 400, "MAPPING_DELETE_FAILED", err.Error(), err)
		return
	}
	_ = a.App.FetchConfigAndApply(r.Context())
	writeJSON(w, 202, output)
}
func (a *API) toggleMapping(w http.ResponseWriter, r *http.Request) {
	var input map[string]interface{}
	if !decodeJSON(w, r, &input) {
		return
	}
	var output interface{}
	if err := a.App.Proxy(r.Context(), "POST", "/api/v1/mappings/"+chi.URLParam(r, "id")+"/toggle", input, r.Header.Get("X-CSRF-Token"), &output, r.Header.Get("Idempotency-Key")); err != nil {
		problem(w, r, 400, "MAPPING_TOGGLE_FAILED", err.Error(), err)
		return
	}
	_ = a.App.FetchConfigAndApply(r.Context())
	writeJSON(w, 200, output)
}

func (a *API) domains(w http.ResponseWriter, r *http.Request) {
	var output interface{}
	if err := a.App.Proxy(r.Context(), "GET", "/api/v1/domains", nil, "", &output); err != nil {
		problem(w, r, 503, "SERVER_UNAVAILABLE", "Server Panel 暂不可达。", err)
		return
	}
	a.markDataSource(w)
	writeJSON(w, 200, output)
}

func (a *API) operations(w http.ResponseWriter, r *http.Request) {
	var output interface{}
	if err := a.App.Proxy(r.Context(), "GET", "/api/v1/operations", nil, "", &output); err != nil {
		problem(w, r, 503, "SERVER_UNAVAILABLE", "Server Panel 暂不可达。", err)
		return
	}
	a.markDataSource(w)
	writeJSON(w, 200, output)
}

func (a *API) createDomain(w http.ResponseWriter, r *http.Request) {
	var input map[string]interface{}
	if !decodeJSON(w, r, &input) {
		return
	}
	var output interface{}
	if err := a.App.Proxy(r.Context(), "POST", "/api/v1/domains", input, r.Header.Get("X-CSRF-Token"), &output, r.Header.Get("Idempotency-Key")); err != nil {
		problem(w, r, 400, "DOMAIN_CREATE_FAILED", err.Error(), err)
		return
	}
	_ = a.App.FetchConfigAndApply(r.Context())
	writeJSON(w, 202, output)
}

func (a *API) deleteDomain(w http.ResponseWriter, r *http.Request) {
	var output interface{}
	if err := a.App.Proxy(r.Context(), "DELETE", "/api/v1/domains/"+chi.URLParam(r, "id"), nil, r.Header.Get("X-CSRF-Token"), &output, r.Header.Get("Idempotency-Key")); err != nil {
		problem(w, r, 400, "DOMAIN_DELETE_FAILED", err.Error(), err)
		return
	}
	_ = a.App.FetchConfigAndApply(r.Context())
	writeJSON(w, 202, output)
}

func (a *API) domainDNSAction(w http.ResponseWriter, r *http.Request) {
	var input map[string]interface{}
	if !decodeJSON(w, r, &input) {
		return
	}
	var output interface{}
	path := "/api/v1/domains/" + chi.URLParam(r, "id") + "/dns-action"
	if err := a.App.Proxy(r.Context(), "POST", path, input, r.Header.Get("X-CSRF-Token"), &output, r.Header.Get("Idempotency-Key")); err != nil {
		problem(w, r, 400, "DNS_ACTION_FAILED", err.Error(), err)
		return
	}
	writeJSON(w, 202, output)
}
func (a *API) config(w http.ResponseWriter, r *http.Request) {
	var output interface{}
	if err := a.App.Proxy(r.Context(), "GET", "/api/v1/config/full", nil, "", &output); err != nil {
		problem(w, r, 503, "SERVER_UNAVAILABLE", "Server Panel 暂不可达。", err)
		return
	}
	a.markDataSource(w)
	writeJSON(w, 200, output)
}
func (a *API) sync(w http.ResponseWriter, r *http.Request) {
	if err := a.App.FetchConfigAndApply(r.Context()); err != nil {
		problem(w, r, 400, "SYNC_FAILED", err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"ok": true, "status": a.App.SupervisorStatus()})
}
func (a *API) localStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, a.App.SupervisorStatus())
}
func (a *API) logs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]interface{}{"items": []map[string]string{{"level": "info", "message": "本地日志由 Supervisor 脱敏收集；当前版本不展示秘密。", "time": time.Now().UTC().Format(time.RFC3339Nano)}}})
}

func (a *API) markDataSource(w http.ResponseWriter) {
	if !a.App.ServerReachable() {
		w.Header().Set("X-Panel-Data", "cached")
		w.Header().Set("Warning", `110 - "Server Panel unavailable; cached read-only data"`)
	} else {
		w.Header().Set("X-Panel-Data", "server")
	}
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target interface{}) bool {
	defer r.Body.Close()
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		problem(w, r, 400, "INVALID_JSON", "请求格式不正确。")
		return false
	}
	var extra interface{}
	if err := decoder.Decode(&extra); err != io.EOF {
		problem(w, r, 400, "INVALID_JSON", "请求体只能包含一个 JSON 值。")
		return false
	}
	return true
}

func hostAllowed(requestHost, configured string) bool {
	requestHost = strings.TrimSpace(strings.TrimSuffix(requestHost, "."))
	if requestHost == "" {
		return false
	}
	requestName, requestPort, err := net.SplitHostPort(requestHost)
	if err != nil {
		requestName = strings.Trim(requestHost, "[]")
		requestPort = ""
	}
	requestName = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(requestName), "."))
	for _, candidate := range strings.Split(configured, ",") {
		candidate = strings.TrimSpace(strings.TrimSuffix(candidate, "."))
		if candidate == "" {
			continue
		}
		candidateName, candidatePort, splitErr := net.SplitHostPort(candidate)
		if splitErr != nil {
			candidateName = strings.Trim(candidate, "[]")
			candidatePort = ""
		}
		candidateName = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(candidateName), "."))
		if candidateName == requestName && (candidatePort == "" || candidatePort == requestPort) {
			return true
		}
	}
	return false
}
func writeJSON(w http.ResponseWriter, status int, value interface{}) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return
	}
	if status >= 200 && status < 300 {
		var object map[string]interface{}
		if json.Unmarshal(encoded, &object) == nil && object != nil {
			if _, exists := object["request_id"]; !exists {
				if requestID := w.Header().Get("X-Request-ID"); requestID != "" {
					object["request_id"] = requestID
					if encoded, err = json.Marshal(object); err != nil {
						return
					}
				}
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(append(encoded, '\n'))
}

func problem(w http.ResponseWriter, r *http.Request, status int, code, detail string, causes ...error) {
	for _, cause := range causes {
		var remote app.RemoteError
		if errors.As(cause, &remote) {
			status = remote.Status
			if remote.Code != "" {
				code = remote.Code
			}
			if remote.Detail != "" {
				detail = remote.Detail
			}
			break
		}
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"type": "https://docs.example.invalid/problems/" + strings.ToLower(strings.ReplaceAll(code, "_", "-")), "title": code, "status": status, "detail": detail, "instance": r.URL.Path, "code": code, "request_id": requestID(r)})
}

func requestID(r *http.Request) string {
	value, _ := r.Context().Value(requestIDKey).(string)
	return value
}
