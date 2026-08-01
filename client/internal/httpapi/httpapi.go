package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/ricardo/frp-panel-platform/client/internal/app"
)

type API struct{ App *app.App }

func New(a *app.App) *API { return &API{App: a} }

func (a *API) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(a.headers, a.cors, a.localAuth)
	r.Get("/healthz", a.health)
	r.Get("/", a.app)
	r.Handle("/assets/*", http.StripPrefix("/assets/", http.FileServer(http.Dir(filepath.Join(a.webDir(), "assets")))))
	r.Get("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join(a.webDir(), "favicon.svg"))
	})
	r.Handle("/favicon.svg", http.FileServer(http.Dir(a.webDir())))
	r.Post("/api/v1/login", a.login)
	r.Group(func(r chi.Router) {
		r.Use(a.sessionRequired)
		r.Post("/api/v1/logout", a.logout)
		r.Post("/api/v1/password", a.password)
		r.Get("/api/v1/session", a.session)
		r.Get("/api/v1/dashboard", a.dashboard)
		r.Get("/api/v1/mappings", a.mappings)
		r.Post("/api/v1/mappings", a.createMapping)
		r.Put("/api/v1/mappings/{id}", a.updateMapping)
		r.Delete("/api/v1/mappings/{id}", a.deleteMapping)
		r.Post("/api/v1/mappings/{id}/toggle", a.toggleMapping)
		r.Get("/api/v1/domains", a.domains)
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
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token")
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
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { next.ServeHTTP(w, r) })
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
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	session, err := a.App.Login(r.Context(), input.ServerPanelURL, input.Username, input.Password)
	if err != nil {
		problem(w, r, 401, "AUTH_INVALID_CREDENTIALS", err.Error())
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "frp_client_session", Value: a.App.SessionCookie(), Path: "/", HttpOnly: true, Secure: false, SameSite: http.SameSiteStrictMode, MaxAge: 1800})
	writeJSON(w, 200, session)
}
func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	_ = a.App.Logout(r.Context())
	http.SetCookie(w, &http.Cookie{Name: "frp_client_session", Value: "", Path: "/", HttpOnly: true, MaxAge: -1, SameSite: http.SameSiteStrictMode})
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
func (a *API) session(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, a.App.Session()) }
func (a *API) dashboard(w http.ResponseWriter, r *http.Request) {
	var output interface{}
	if err := a.App.Proxy(r.Context(), "GET", "/api/v1/dashboard", nil, "", &output); err != nil {
		problem(w, r, 503, "SERVER_UNAVAILABLE", "Server Panel 暂不可达，当前仅可查看本地缓存。", err)
		return
	}
	writeJSON(w, 200, output)
}
func (a *API) mappings(w http.ResponseWriter, r *http.Request) {
	var output interface{}
	if err := a.App.Proxy(r.Context(), "GET", "/api/v1/mappings", nil, "", &output); err != nil {
		problem(w, r, 503, "SERVER_UNAVAILABLE", "Server Panel 暂不可达。", err)
		return
	}
	writeJSON(w, 200, output)
}
func (a *API) createMapping(w http.ResponseWriter, r *http.Request) {
	var input map[string]interface{}
	if !decodeJSON(w, r, &input) {
		return
	}
	var output interface{}
	if err := a.App.Proxy(r.Context(), "POST", "/api/v1/mappings", input, r.Header.Get("X-CSRF-Token"), &output); err != nil {
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
	if err := a.App.Proxy(r.Context(), "PUT", "/api/v1/mappings/"+chi.URLParam(r, "id"), input, r.Header.Get("X-CSRF-Token"), &output); err != nil {
		problem(w, r, 400, "MAPPING_UPDATE_FAILED", err.Error(), err)
		return
	}
	_ = a.App.FetchConfigAndApply(r.Context())
	writeJSON(w, 200, output)
}
func (a *API) deleteMapping(w http.ResponseWriter, r *http.Request) {
	var output interface{}
	path := "/api/v1/mappings/" + chi.URLParam(r, "id")
	if err := a.App.Proxy(r.Context(), "DELETE", path, nil, r.Header.Get("X-CSRF-Token"), &output); err != nil {
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
	if err := a.App.Proxy(r.Context(), "POST", "/api/v1/mappings/"+chi.URLParam(r, "id")+"/toggle", input, r.Header.Get("X-CSRF-Token"), &output); err != nil {
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
	writeJSON(w, 200, output)
}

func (a *API) createDomain(w http.ResponseWriter, r *http.Request) {
	var input map[string]interface{}
	if !decodeJSON(w, r, &input) {
		return
	}
	var output interface{}
	if err := a.App.Proxy(r.Context(), "POST", "/api/v1/domains", input, r.Header.Get("X-CSRF-Token"), &output); err != nil {
		problem(w, r, 400, "DOMAIN_CREATE_FAILED", err.Error(), err)
		return
	}
	_ = a.App.FetchConfigAndApply(r.Context())
	writeJSON(w, 202, output)
}

func (a *API) deleteDomain(w http.ResponseWriter, r *http.Request) {
	var output interface{}
	if err := a.App.Proxy(r.Context(), "DELETE", "/api/v1/domains/"+chi.URLParam(r, "id"), nil, r.Header.Get("X-CSRF-Token"), &output); err != nil {
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
	if err := a.App.Proxy(r.Context(), "POST", path, input, r.Header.Get("X-CSRF-Token"), &output); err != nil {
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

func decodeJSON(w http.ResponseWriter, r *http.Request, target interface{}) bool {
	defer r.Body.Close()
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		problem(w, r, 400, "INVALID_JSON", "请求格式不正确。")
		return false
	}
	return true
}
func writeJSON(w http.ResponseWriter, status int, value interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
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
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"type": "https://docs.example.invalid/problems/" + strings.ToLower(strings.ReplaceAll(code, "_", "-")), "title": code, "status": status, "detail": detail, "instance": r.URL.Path})
}
func _unused(_ context.Context, _ fmt.Stringer) {}
