package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/ricardo/frp-panel-platform/server/internal/auth"
	"github.com/ricardo/frp-panel-platform/server/internal/config"
	"github.com/ricardo/frp-panel-platform/server/internal/crypto"
	"github.com/ricardo/frp-panel-platform/server/internal/db"
	"golang.org/x/net/idna"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrSessionInvalid     = errors.New("session invalid")
	ErrForbidden          = errors.New("forbidden")
	ErrNotFound           = errors.New("not found")
	ErrConfigConflict     = errors.New("configuration version conflict")
	ErrIdempotencyReuse   = errors.New("idempotency key reused")
	ErrPortReserved       = errors.New("port already reserved")
)

type App struct {
	DB      *db.DB
	Config  config.Config
	Crypto  *crypto.Manager
	Started time.Time
}

type AuthContext struct {
	SessionID  string
	UserID     string
	Username   string
	Role       string
	Status     string
	Generation int64
	Channel    string
	MustChange bool
	ExpiresAt  time.Time
}

type UserSummary struct {
	ID                 string `json:"id"`
	Username           string `json:"username"`
	Role               string `json:"role"`
	Status             string `json:"status"`
	MustChangePassword bool   `json:"must_change_password"`
}

type LoginResult struct {
	Token          string      `json:"token"`
	SessionID      string      `json:"-"`
	SessionExpires time.Time   `json:"session_expires_at"`
	User           UserSummary `json:"user"`
	RequestID      string      `json:"request_id,omitempty"`
}

type Mapping struct {
	ID              string `json:"id"`
	UserID          string `json:"user_id"`
	Name            string `json:"name"`
	ProxyType       string `json:"proxy_type"`
	LifecycleStatus string `json:"lifecycle_status"`
	DesiredState    string `json:"desired_state"`
	ObservedState   string `json:"observed_state"`
	Revision        int64  `json:"revision"`
	LocalIP         string `json:"local_ip"`
	LocalPort       int    `json:"local_port"`
	RemotePort      *int   `json:"remote_port,omitempty"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}

type MappingRequest struct {
	Name                  string `json:"name"`
	ProxyType             string `json:"proxy_type"`
	LocalIP               string `json:"local_ip"`
	LocalPort             int    `json:"local_port"`
	RemotePort            *int   `json:"remote_port"`
	ExpectedConfigVersion *int64 `json:"expected_config_version"`
}

type Domain struct {
	ID           string `json:"id"`
	MappingID    string `json:"mapping_id"`
	Hostname     string `json:"hostname"`
	Normalized   string `json:"normalized_domain"`
	HTTPSMode    string `json:"https_mode"`
	HTTPRedirect bool   `json:"http_redirect"`
	Status       string `json:"status"`
	Revision     int64  `json:"revision"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
}

type DomainRequest struct {
	MappingID             string `json:"mapping_id"`
	Hostname              string `json:"hostname"`
	HTTPSMode             string `json:"https_mode"`
	HTTPRedirect          bool   `json:"http_redirect"`
	ExpectedConfigVersion *int64 `json:"expected_config_version"`
}

type ApplyResultRequest struct {
	Status             string `json:"status"`
	ConfigVersion      int64  `json:"config_version"`
	AppliedConfigHash  string `json:"applied_config_hash"`
	ErrorCode          string `json:"error_code"`
	ErrorMessage       string `json:"error_message"`
	ClientPanelVersion string `json:"client_panel_version"`
	FRPCVersion        string `json:"frpc_version"`
}

type Dashboard struct {
	User                 UserSummary `json:"user"`
	DesiredConfigVersion int64       `json:"desired_config_version"`
	AppliedConfigVersion int64       `json:"applied_config_version"`
	ObservedClientStatus string      `json:"observed_client_status"`
	LastHeartbeatAt      *string     `json:"last_heartbeat_at,omitempty"`
	LastErrorCode        string      `json:"last_error_code,omitempty"`
	LastErrorMessage     string      `json:"last_error_message,omitempty"`
	Mappings             []Mapping   `json:"mappings"`
	Counts               Counts      `json:"counts"`
}

type Counts struct {
	TotalMappings int `json:"total_mappings"`
	Running       int `json:"running"`
	Pending       int `json:"pending"`
	Offline       int `json:"offline"`
	Errors        int `json:"errors"`
}

type ConfigSnapshot struct {
	SchemaVersion     string                 `json:"schema_version"`
	ConfigVersion     int64                  `json:"config_version"`
	UserID            string                 `json:"user_id"`
	SessionGeneration int64                  `json:"session_generation"`
	IssuedAt          string                 `json:"issued_at"`
	ExpiresAt         string                 `json:"expires_at"`
	ConfigHash        string                 `json:"config_hash"`
	SigningKeyID      string                 `json:"signing_key_id"`
	Signature         string                 `json:"signature"`
	Payload           map[string]interface{} `json:"payload"`
}

type UserRecord struct {
	UserSummary
	CreatedAt        string `json:"created_at"`
	DesiredConfig    int64  `json:"desired_config_version"`
	AppliedConfig    int64  `json:"applied_config_version"`
	ActiveSessionGen int64  `json:"active_session_generation"`
}

func New(dbConn *db.DB, cfg config.Config, secrets *crypto.Manager) *App {
	return &App{DB: dbConn, Config: cfg, Crypto: secrets, Started: time.Now().UTC()}
}

func (a *App) EnsureAdmin(ctx context.Context) (string, error) {
	var count int
	if err := a.DB.QueryRowContext(ctx, `SELECT COUNT(1) FROM users WHERE role='admin' AND status <> 'deleted'`).Scan(&count); err != nil {
		return "", err
	}
	if count > 0 {
		return "", nil
	}
	password := a.Config.AdminPassword
	if password == "" {
		var err error
		password, err = config.GenerateInitialPassword()
		if err != nil {
			return "", err
		}
		path := fmt.Sprintf("%s/initial-admin.txt", a.Config.DataDir)
		if err := osWritePrivate(path, []byte("username=admin\npassword="+password+"\n")); err != nil {
			return "", err
		}
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return "", err
	}
	now := nowString()
	userID := uuid.NewString()
	secret, err := randomSecret()
	if err != nil {
		return "", err
	}
	ciphertext, nonce, err := a.Crypto.Encrypt([]byte(secret), "user:"+userID+":frp_secret:v1")
	if err != nil {
		return "", err
	}
	secretHash := sha256Hex(secret)
	_, err = a.DB.ExecContext(ctx, `
		INSERT INTO users(id, username, password_hash, role, status, must_change_password, active_session_generation, created_at, updated_at)
		VALUES(?, 'admin', ?, 'admin', 'active', ?, 1, ?, ?)`, userID, hash, boolInt(a.Config.AdminPassword == ""), now, now)
	if err != nil {
		return "", err
	}
	_, err = a.DB.ExecContext(ctx, `INSERT INTO frp_credentials(id,user_id,frp_username,secret_hash,secret_ciphertext,secret_nonce,created_at) VALUES(?,?,?,?,?,?,?)`, uuid.NewString(), userID, "admin-"+shortID(userID), secretHash, ciphertext, nonce, now)
	return passwordIfNeeded(a.Config.AdminPassword, password), err
}

func passwordIfNeeded(configured, generated string) string {
	if configured != "" {
		return ""
	}
	return generated
}

func (a *App) Login(ctx context.Context, username, password, channel, sourceIP, userAgent string) (LoginResult, error) {
	if strings.TrimSpace(username) == "" || len(password) < 12 {
		return LoginResult{}, ErrInvalidCredentials
	}
	tx, err := a.DB.BeginTx(ctx, nil)
	if err != nil {
		return LoginResult{}, err
	}
	defer tx.Rollback()
	var user UserSummary
	var passwordHash string
	var generation int64
	if err := tx.QueryRowContext(ctx, `SELECT id,username,password_hash,role,status,must_change_password,active_session_generation FROM users WHERE username=? AND status <> 'deleted'`, username).Scan(&user.ID, &user.Username, &passwordHash, &user.Role, &user.Status, &user.MustChangePassword, &generation); err != nil {
		return LoginResult{}, ErrInvalidCredentials
	}
	if !auth.VerifyPassword(passwordHash, password) {
		return LoginResult{}, ErrInvalidCredentials
	}
	if user.Status != "active" {
		return LoginResult{}, errors.New("user disabled")
	}
	if channel == "admin_panel" && user.Role != "admin" {
		return LoginResult{}, ErrInvalidCredentials
	}
	if channel == "client_panel" && user.Role != "user" {
		return LoginResult{}, ErrInvalidCredentials
	}
	if channel == "client_panel" {
		if _, err := tx.ExecContext(ctx, `UPDATE sessions SET revoked_at=?, revoke_reason='SESSION_REPLACED' WHERE user_id=? AND login_channel='client_panel' AND revoked_at IS NULL`, nowString(), user.ID); err != nil {
			return LoginResult{}, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE users SET active_session_generation=active_session_generation+1, updated_at=? WHERE id=?`, nowString(), user.ID); err != nil {
			return LoginResult{}, err
		}
		if err := tx.QueryRowContext(ctx, `SELECT active_session_generation FROM users WHERE id=?`, user.ID).Scan(&generation); err != nil {
			return LoginResult{}, err
		}
	}
	token, err := randomToken()
	if err != nil {
		return LoginResult{}, err
	}
	sessionID := uuid.NewString()
	now := time.Now().UTC()
	expires := now.Add(time.Duration(a.Config.SessionTTLHours) * time.Hour)
	idle := now.Add(30 * time.Minute)
	if _, err := tx.ExecContext(ctx, `INSERT INTO sessions(id,user_id,session_hash,login_channel,session_generation,source_ip,user_agent,expires_at,idle_expires_at,last_seen_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, sessionID, user.ID, sha256Hex(token), channel, generation, sourceIP, userAgent, expires.Format(time.RFC3339Nano), idle.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
		return LoginResult{}, err
	}
	if channel == "client_panel" {
		runtimeToken, err := randomToken()
		if err != nil {
			return LoginResult{}, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO frp_runtime_credentials(id,user_id,server_session_id,session_generation,token_hash,expires_at,created_at) VALUES(?,?,?,?,?,?,?)`, uuid.NewString(), user.ID, sessionID, generation, sha256Hex(runtimeToken), expires.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
			return LoginResult{}, err
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO user_runtime_state(user_id,active_server_session_id,observed_client_status,updated_at) VALUES(?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET active_server_session_id=excluded.active_server_session_id, observed_client_status='online', updated_at=excluded.updated_at`, user.ID, sessionID, "online", now.Format(time.RFC3339Nano)); err != nil {
		return LoginResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return LoginResult{}, err
	}
	return LoginResult{Token: token, SessionID: sessionID, SessionExpires: expires, User: user}, nil
}

func (a *App) Authenticate(ctx context.Context, bearer string) (AuthContext, error) {
	bearer = strings.TrimSpace(strings.TrimPrefix(bearer, "Bearer "))
	if bearer == "" {
		return AuthContext{}, ErrSessionInvalid
	}
	var ac AuthContext
	var mustChange int
	var expires, idle, revokedAt string
	if err := a.DB.QueryRowContext(ctx, `SELECT s.id,s.user_id,u.username,u.role,u.status,u.must_change_password,s.session_generation,s.login_channel,s.expires_at,s.idle_expires_at,COALESCE(s.revoked_at,'') FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.session_hash=?`, sha256Hex(bearer)).Scan(&ac.SessionID, &ac.UserID, &ac.Username, &ac.Role, &ac.Status, &mustChange, &ac.Generation, &ac.Channel, &expires, &idle, &revokedAt); err != nil {
		return AuthContext{}, ErrSessionInvalid
	}
	if revokedAt != "" {
		return AuthContext{}, errors.New("session replaced")
	}
	ac.MustChange = mustChange == 1
	ac.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expires)
	idleAt, _ := time.Parse(time.RFC3339Nano, idle)
	now := time.Now().UTC()
	if ac.Status != "active" || now.After(ac.ExpiresAt) || now.After(idleAt) {
		return AuthContext{}, ErrSessionInvalid
	}
	var currentGeneration int64
	if err := a.DB.QueryRowContext(ctx, `SELECT active_session_generation FROM users WHERE id=?`, ac.UserID).Scan(&currentGeneration); err != nil || currentGeneration != ac.Generation && ac.Channel == "client_panel" {
		return AuthContext{}, errors.New("session replaced")
	}
	_, _ = a.DB.ExecContext(ctx, `UPDATE sessions SET last_seen_at=?, idle_expires_at=? WHERE id=? AND revoked_at IS NULL`, now.Format(time.RFC3339Nano), now.Add(30*time.Minute).Format(time.RFC3339Nano), ac.SessionID)
	return ac, nil
}

func (a *App) Logout(ctx context.Context, ac AuthContext, reason string) error {
	_, err := a.DB.ExecContext(ctx, `UPDATE sessions SET revoked_at=?, revoke_reason=? WHERE id=? AND revoked_at IS NULL`, nowString(), reason, ac.SessionID)
	if err != nil {
		return err
	}
	_, _ = a.DB.ExecContext(ctx, `UPDATE frp_runtime_credentials SET revoked_at=? WHERE server_session_id=? AND revoked_at IS NULL`, nowString(), ac.SessionID)
	_, _ = a.DB.ExecContext(ctx, `UPDATE user_runtime_state SET active_server_session_id=NULL, observed_client_status='offline', updated_at=? WHERE user_id=? AND active_server_session_id=?`, nowString(), ac.UserID, ac.SessionID)
	return nil
}

func (a *App) ChangePassword(ctx context.Context, ac AuthContext, currentPassword, newPassword string) error {
	if len(newPassword) < 12 {
		return fmt.Errorf("password must be at least 12 characters")
	}
	var currentHash string
	if err := a.DB.QueryRowContext(ctx, `SELECT password_hash FROM users WHERE id=?`, ac.UserID).Scan(&currentHash); err != nil || !auth.VerifyPassword(currentHash, currentPassword) {
		return ErrInvalidCredentials
	}
	hash, err := auth.HashPassword(newPassword)
	if err != nil {
		return err
	}
	_, err = a.DB.ExecContext(ctx, `UPDATE users SET password_hash=?, must_change_password=0, auth_version=auth_version+1, updated_at=? WHERE id=?`, hash, nowString(), ac.UserID)
	if err == nil {
		_ = a.Audit(ctx, ac, "password_changed", "user", ac.UserID, "success", nil, "")
	}
	return err
}

func (a *App) Dashboard(ctx context.Context, ac AuthContext) (Dashboard, error) {
	var out Dashboard
	var mustChange int
	if err := a.DB.QueryRowContext(ctx, `SELECT id,username,role,status,must_change_password,desired_config_version,applied_config_version FROM users WHERE id=?`, ac.UserID).Scan(&out.User.ID, &out.User.Username, &out.User.Role, &out.User.Status, &mustChange, &out.DesiredConfigVersion, &out.AppliedConfigVersion); err != nil {
		return out, err
	}
	out.User.MustChangePassword = mustChange == 1
	var lastHeartbeat, lastErrorCode, lastErrorMessage string
	_ = a.DB.QueryRowContext(ctx, `SELECT observed_client_status,COALESCE(last_heartbeat_at,''),COALESCE(last_error_code,''),COALESCE(last_error_message,'') FROM user_runtime_state WHERE user_id=?`, ac.UserID).Scan(&out.ObservedClientStatus, &lastHeartbeat, &lastErrorCode, &lastErrorMessage)
	if lastHeartbeat != "" {
		out.LastHeartbeatAt = &lastHeartbeat
	}
	out.LastErrorCode, out.LastErrorMessage = lastErrorCode, lastErrorMessage
	out.Mappings, _ = a.ListMappings(ctx, ac.UserID)
	out.Counts.TotalMappings = len(out.Mappings)
	for _, m := range out.Mappings {
		switch m.LifecycleStatus {
		case "running":
			out.Counts.Running++
		case "offline":
			out.Counts.Offline++
		case "config_error":
			out.Counts.Errors++
		default:
			out.Counts.Pending++
		}
	}
	return out, nil
}

func (a *App) ListMappings(ctx context.Context, userID string) ([]Mapping, error) {
	rows, err := a.DB.QueryContext(ctx, `SELECT m.id,m.user_id,m.name,m.proxy_type,m.lifecycle_status,m.desired_state,m.observed_state,COALESCE(r.revision,0),COALESCE(r.local_ip,''),COALESCE(r.local_port,0),r.remote_port,m.created_at,m.updated_at FROM mappings m LEFT JOIN mapping_revisions r ON r.id=COALESCE(m.pending_revision_id,m.active_revision_id) WHERE m.user_id=? AND m.lifecycle_status <> 'deleted' ORDER BY m.created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]Mapping, 0)
	for rows.Next() {
		var item Mapping
		if err := rows.Scan(&item.ID, &item.UserID, &item.Name, &item.ProxyType, &item.LifecycleStatus, &item.DesiredState, &item.ObservedState, &item.Revision, &item.LocalIP, &item.LocalPort, &item.RemotePort, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (a *App) CreateMapping(ctx context.Context, ac AuthContext, req MappingRequest, idempotencyKey string) (Mapping, error) {
	if err := validateMapping(req); err != nil {
		return Mapping{}, err
	}
	if idempotencyKey == "" {
		idempotencyKey = uuid.NewString()
	}
	bodyHash := requestHash(req)
	tx, err := a.DB.BeginTx(ctx, nil)
	if err != nil {
		return Mapping{}, err
	}
	defer tx.Rollback()
	var existingHash string
	var existingBody string
	if err := tx.QueryRowContext(ctx, `SELECT request_body_hash,response_body_json FROM idempotency_records WHERE user_id=? AND session_generation=? AND http_method='POST' AND normalized_path='/api/v1/mappings' AND idempotency_key=?`, ac.UserID, ac.Generation, idempotencyKey).Scan(&existingHash, &existingBody); err == nil {
		if existingHash != bodyHash {
			return Mapping{}, ErrIdempotencyReuse
		}
		var item Mapping
		if err := json.Unmarshal([]byte(existingBody), &item); err != nil {
			return Mapping{}, err
		}
		return item, nil
	}
	var desired int64
	var maxMappings int
	if err := tx.QueryRowContext(ctx, `SELECT desired_config_version,max_mappings FROM users WHERE id=? AND status='active'`, ac.UserID).Scan(&desired, &maxMappings); err != nil {
		return Mapping{}, ErrForbidden
	}
	if req.ExpectedConfigVersion != nil && *req.ExpectedConfigVersion != desired {
		return Mapping{}, ErrConfigConflict
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM mappings WHERE user_id=? AND lifecycle_status <> 'deleted'`, ac.UserID).Scan(&count); err != nil || count >= maxMappings {
		return Mapping{}, fmt.Errorf("mapping quota exceeded")
	}
	remotePort := req.RemotePort
	if req.ProxyType == "tcp" || req.ProxyType == "udp" {
		if remotePort == nil || *remotePort == 0 {
			port, err := allocatePort(ctx, tx, a.Config.PortStart, a.Config.PortEnd)
			if err != nil {
				return Mapping{}, err
			}
			remotePort = &port
		}
		if *remotePort < a.Config.PortStart || *remotePort > a.Config.PortEnd || *remotePort == a.Config.FRPSBindPort {
			return Mapping{}, fmt.Errorf("port not allowed")
		}
	}
	now := nowString()
	mappingID, revisionID := uuid.NewString(), uuid.NewString()
	if _, err := tx.ExecContext(ctx, `INSERT INTO mappings(id,user_id,name,proxy_type,lifecycle_status,desired_state,observed_state,pending_revision_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, mappingID, ac.UserID, strings.TrimSpace(req.Name), req.ProxyType, "pending_apply", "enabled", "offline", revisionID, now, now); err != nil {
		return Mapping{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO mapping_revisions(id,mapping_id,revision,local_ip,local_port,remote_port,status,created_at) VALUES(?,?,?,?,?,?,?,?)`, revisionID, mappingID, 1, req.LocalIP, req.LocalPort, nullablePort(remotePort), "pending", now); err != nil {
		return Mapping{}, err
	}
	if remotePort != nil {
		if _, err := tx.ExecContext(ctx, `INSERT INTO port_leases(id,server_id,mapping_id,mapping_revision_id,remote_port,lease_role,created_at) VALUES(?,?,?,?,?,?,?)`, uuid.NewString(), "default", mappingID, revisionID, *remotePort, "active", now); err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				return Mapping{}, ErrPortReserved
			}
			return Mapping{}, err
		}
	}
	newVersion := desired + 1
	if _, err := tx.ExecContext(ctx, `UPDATE users SET desired_config_version=?, updated_at=? WHERE id=?`, newVersion, now, ac.UserID); err != nil {
		return Mapping{}, err
	}
	operationID := uuid.NewString()
	if _, err := tx.ExecContext(ctx, `INSERT INTO operations(id,user_id,resource_type,resource_id,operation_type,status,phase,step,idempotency_key,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, operationID, ac.UserID, "mapping", mappingID, "create", "pending", "mapping", "reserved", idempotencyKey, now, now); err != nil {
		return Mapping{}, err
	}
	item := Mapping{ID: mappingID, UserID: ac.UserID, Name: strings.TrimSpace(req.Name), ProxyType: req.ProxyType, LifecycleStatus: "pending_apply", DesiredState: "enabled", ObservedState: "offline", Revision: 1, LocalIP: req.LocalIP, LocalPort: req.LocalPort, RemotePort: remotePort, CreatedAt: now, UpdatedAt: now}
	encoded, _ := json.Marshal(item)
	if _, err := tx.ExecContext(ctx, `INSERT INTO idempotency_records(id,user_id,session_generation,http_method,normalized_path,idempotency_key,request_body_hash,response_status,response_body_json,operation_id,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, uuid.NewString(), ac.UserID, ac.Generation, "POST", "/api/v1/mappings", idempotencyKey, bodyHash, 201, string(encoded), operationID, time.Now().UTC().Add(24*time.Hour).Format(time.RFC3339Nano), now); err != nil {
		return Mapping{}, err
	}
	if err := tx.Commit(); err != nil {
		return Mapping{}, err
	}
	_ = a.Audit(ctx, ac, "mapping_created", "mapping", mappingID, "success", map[string]interface{}{"proxy_type": req.ProxyType, "revision": 1}, operationID)
	return item, nil
}

func (a *App) UpdateMapping(ctx context.Context, ac AuthContext, mappingID string, req MappingRequest, idempotencyKey string) (Mapping, error) {
	if err := validateMapping(req); err != nil {
		return Mapping{}, err
	}
	tx, err := a.DB.BeginTx(ctx, nil)
	if err != nil {
		return Mapping{}, err
	}
	defer tx.Rollback()
	var current Mapping
	var activeID, pendingID string
	if err := tx.QueryRowContext(ctx, `SELECT m.id,m.user_id,m.name,m.proxy_type,m.lifecycle_status,m.desired_state,m.observed_state,COALESCE(r.revision,0),COALESCE(r.local_ip,''),COALESCE(r.local_port,0),r.remote_port,m.created_at,m.updated_at,m.active_revision_id,COALESCE(m.pending_revision_id,'') FROM mappings m LEFT JOIN mapping_revisions r ON r.id=COALESCE(m.pending_revision_id,m.active_revision_id) WHERE m.id=? AND m.user_id=? AND m.lifecycle_status <> 'deleted'`, mappingID, ac.UserID).Scan(&current.ID, &current.UserID, &current.Name, &current.ProxyType, &current.LifecycleStatus, &current.DesiredState, &current.ObservedState, &current.Revision, &current.LocalIP, &current.LocalPort, &current.RemotePort, &current.CreatedAt, &current.UpdatedAt, &activeID, &pendingID); err != nil {
		return Mapping{}, ErrNotFound
	}
	var desired int64
	if err := tx.QueryRowContext(ctx, `SELECT desired_config_version FROM users WHERE id=?`, ac.UserID).Scan(&desired); err != nil {
		return Mapping{}, err
	}
	if req.ExpectedConfigVersion != nil && *req.ExpectedConfigVersion != desired {
		return Mapping{}, ErrConfigConflict
	}
	remotePort := req.RemotePort
	if req.ProxyType == "tcp" || req.ProxyType == "udp" {
		if remotePort == nil || *remotePort == 0 {
			remotePort = current.RemotePort
		}
		if remotePort == nil || *remotePort < a.Config.PortStart || *remotePort > a.Config.PortEnd {
			return Mapping{}, fmt.Errorf("port not allowed")
		}
	}
	now := nowString()
	newRevision := current.Revision + 1
	revisionID := uuid.NewString()
	if _, err := tx.ExecContext(ctx, `INSERT INTO mapping_revisions(id,mapping_id,revision,local_ip,local_port,remote_port,status,created_at) VALUES(?,?,?,?,?,?,?,?)`, revisionID, mappingID, newRevision, req.LocalIP, req.LocalPort, nullablePort(remotePort), "pending", now); err != nil {
		return Mapping{}, err
	}
	if remotePort != nil && (current.RemotePort == nil || *remotePort != *current.RemotePort) {
		if _, err := tx.ExecContext(ctx, `INSERT INTO port_leases(id,server_id,mapping_id,mapping_revision_id,remote_port,lease_role,created_at) VALUES(?,?,?,?,?,?,?)`, uuid.NewString(), "default", mappingID, revisionID, *remotePort, "pending", now); err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				return Mapping{}, ErrPortReserved
			}
			return Mapping{}, err
		}
	}
	newVersion := desired + 1
	if _, err := tx.ExecContext(ctx, `UPDATE mappings SET name=?,proxy_type=?,lifecycle_status='pending_apply',pending_revision_id=?,updated_at=? WHERE id=? AND user_id=?`, strings.TrimSpace(req.Name), req.ProxyType, revisionID, now, mappingID, ac.UserID); err != nil {
		return Mapping{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users SET desired_config_version=?,updated_at=? WHERE id=?`, newVersion, now, ac.UserID); err != nil {
		return Mapping{}, err
	}
	operationID := uuid.NewString()
	if _, err := tx.ExecContext(ctx, `INSERT INTO operations(id,user_id,resource_type,resource_id,operation_type,status,phase,step,idempotency_key,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, operationID, ac.UserID, "mapping", mappingID, "update", "pending", "mapping", "reserved", idempotencyKey, now, now); err != nil {
		return Mapping{}, err
	}
	current.Name, current.ProxyType, current.LifecycleStatus, current.LocalIP, current.LocalPort, current.RemotePort, current.Revision, current.UpdatedAt = strings.TrimSpace(req.Name), req.ProxyType, "pending_apply", req.LocalIP, req.LocalPort, remotePort, newRevision, now
	current.ObservedState = "offline"
	if err := tx.Commit(); err != nil {
		return Mapping{}, err
	}
	_ = a.Audit(ctx, ac, "mapping_updated", "mapping", mappingID, "success", map[string]interface{}{"revision": newRevision}, operationID)
	return current, nil
}

func (a *App) DeleteMapping(ctx context.Context, ac AuthContext, mappingID string, force bool) (string, error) {
	now := nowString()
	if force {
		result, err := a.DB.ExecContext(ctx, `DELETE FROM mappings WHERE id=? AND user_id=?`, mappingID, ac.UserID)
		if err != nil {
			return "", err
		}
		if n, _ := result.RowsAffected(); n == 0 {
			return "", ErrNotFound
		}
		_, _ = a.DB.ExecContext(ctx, `UPDATE users SET desired_config_version=desired_config_version+1,updated_at=? WHERE id=?`, now, ac.UserID)
		_ = a.Audit(ctx, ac, "mapping_force_deleted", "mapping", mappingID, "success", nil, "")
		return "", nil
	}
	result, err := a.DB.ExecContext(ctx, `UPDATE mappings SET lifecycle_status='deleting',desired_state='disabled',updated_at=? WHERE id=? AND user_id=? AND lifecycle_status <> 'deleted'`, now, mappingID, ac.UserID)
	if err != nil {
		return "", err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return "", ErrNotFound
	}
	_, _ = a.DB.ExecContext(ctx, `UPDATE users SET desired_config_version=desired_config_version+1,updated_at=? WHERE id=?`, now, ac.UserID)
	opID := uuid.NewString()
	_, _ = a.DB.ExecContext(ctx, `INSERT INTO operations(id,user_id,resource_type,resource_id,operation_type,status,phase,step,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, opID, ac.UserID, "mapping", mappingID, "delete", "pending", "client", "awaiting_apply", now, now)
	_ = a.Audit(ctx, ac, "mapping_delete_requested", "mapping", mappingID, "success", nil, opID)
	return opID, nil
}

func (a *App) ToggleMapping(ctx context.Context, ac AuthContext, mappingID string, enabled bool) error {
	state := "disabled"
	if enabled {
		state = "enabled"
	}
	result, err := a.DB.ExecContext(ctx, `UPDATE mappings SET desired_state=?,lifecycle_status=CASE WHEN ?='enabled' THEN 'pending_apply' ELSE 'disabled' END,updated_at=? WHERE id=? AND user_id=? AND lifecycle_status <> 'deleted'`, state, state, nowString(), mappingID, ac.UserID)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	_, _ = a.DB.ExecContext(ctx, `UPDATE users SET desired_config_version=desired_config_version+1,updated_at=? WHERE id=?`, nowString(), ac.UserID)
	return a.Audit(ctx, ac, "mapping_toggled", "mapping", mappingID, "success", map[string]interface{}{"enabled": enabled}, "")
}

func (a *App) ListDomains(ctx context.Context, userID string) ([]Domain, error) {
	rows, err := a.DB.QueryContext(ctx, `SELECT id,mapping_id,hostname,normalized_domain,https_mode,http_redirect,status,revision,created_at,updated_at FROM domain_bindings WHERE user_id=? AND status <> 'deleted' ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]Domain, 0)
	for rows.Next() {
		var item Domain
		var redirect int
		if err := rows.Scan(&item.ID, &item.MappingID, &item.Hostname, &item.Normalized, &item.HTTPSMode, &redirect, &item.Status, &item.Revision, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		item.HTTPRedirect = redirect == 1
		items = append(items, item)
	}
	return items, rows.Err()
}

func (a *App) CreateDomain(ctx context.Context, ac AuthContext, req DomainRequest) (Domain, error) {
	if req.HTTPSMode != "auto_certificate" && req.HTTPSMode != "cloudflare_proxy" && req.HTTPSMode != "http_only" {
		return Domain{}, fmt.Errorf("invalid https mode")
	}
	normalized, err := normalizeDomain(req.Hostname)
	if err != nil {
		return Domain{}, err
	}
	tx, err := a.DB.BeginTx(ctx, nil)
	if err != nil {
		return Domain{}, err
	}
	defer tx.Rollback()
	var desired int64
	if err := tx.QueryRowContext(ctx, `SELECT desired_config_version FROM users WHERE id=? AND status='active'`, ac.UserID).Scan(&desired); err != nil {
		return Domain{}, ErrForbidden
	}
	if req.ExpectedConfigVersion != nil && *req.ExpectedConfigVersion != desired {
		return Domain{}, ErrConfigConflict
	}
	var proxyType, mappingOwner string
	if err := tx.QueryRowContext(ctx, `SELECT user_id,proxy_type FROM mappings WHERE id=? AND lifecycle_status <> 'deleted'`, req.MappingID).Scan(&mappingOwner, &proxyType); err != nil || mappingOwner != ac.UserID || proxyType != "http" {
		return Domain{}, fmt.Errorf("HTTP mapping is required")
	}
	var domainCount, maxDomains int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(1),(SELECT max_domains FROM users WHERE id=?) FROM domain_bindings WHERE user_id=? AND status <> 'deleted'`, ac.UserID, ac.UserID).Scan(&domainCount, &maxDomains); err != nil || domainCount >= maxDomains {
		return Domain{}, fmt.Errorf("domain quota exceeded")
	}
	now := nowString()
	domainID := uuid.NewString()
	if _, err := tx.ExecContext(ctx, `INSERT INTO domain_bindings(id,user_id,mapping_id,hostname,normalized_domain,https_mode,http_redirect,status,revision,created_at,updated_at) VALUES(?,?,?,?,?,?,?,'pending_dns',1,?,?)`, domainID, ac.UserID, req.MappingID, strings.TrimSpace(req.Hostname), normalized, req.HTTPSMode, boolInt(req.HTTPRedirect), now, now); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return Domain{}, fmt.Errorf("domain already reserved")
		}
		return Domain{}, err
	}
	newVersion := desired + 1
	if _, err := tx.ExecContext(ctx, `UPDATE users SET desired_config_version=?,updated_at=? WHERE id=?`, newVersion, now, ac.UserID); err != nil {
		return Domain{}, err
	}
	opID := uuid.NewString()
	if _, err := tx.ExecContext(ctx, `INSERT INTO operations(id,user_id,resource_type,resource_id,operation_type,status,phase,step,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, opID, ac.UserID, "domain", domainID, "create", "pending", "dns", "awaiting_provider", now, now); err != nil {
		return Domain{}, err
	}
	if err := tx.Commit(); err != nil {
		return Domain{}, err
	}
	_ = a.Audit(ctx, ac, "domain_created", "domain", domainID, "pending", map[string]interface{}{"status": "pending_dns"}, opID)
	return Domain{ID: domainID, MappingID: req.MappingID, Hostname: strings.TrimSpace(req.Hostname), Normalized: normalized, HTTPSMode: req.HTTPSMode, HTTPRedirect: req.HTTPRedirect, Status: "pending_dns", Revision: 1, CreatedAt: now, UpdatedAt: now}, nil
}

func (a *App) DeleteDomain(ctx context.Context, ac AuthContext, domainID string) (string, error) {
	now := nowString()
	result, err := a.DB.ExecContext(ctx, `UPDATE domain_bindings SET status='deleting',updated_at=? WHERE id=? AND user_id=? AND status <> 'deleted'`, now, domainID, ac.UserID)
	if err != nil {
		return "", err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return "", ErrNotFound
	}
	_, _ = a.DB.ExecContext(ctx, `UPDATE users SET desired_config_version=desired_config_version+1,updated_at=? WHERE id=?`, now, ac.UserID)
	opID := uuid.NewString()
	_, _ = a.DB.ExecContext(ctx, `INSERT INTO operations(id,user_id,resource_type,resource_id,operation_type,status,phase,step,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, opID, ac.UserID, "domain", domainID, "delete", "pending", "router", "awaiting_client", now, now)
	_ = a.Audit(ctx, ac, "domain_delete_requested", "domain", domainID, "pending", nil, opID)
	return opID, nil
}

func (a *App) FullConfig(ctx context.Context, ac AuthContext) (ConfigSnapshot, error) {
	var version, generation int64
	if err := a.DB.QueryRowContext(ctx, `SELECT desired_config_version,active_session_generation FROM users WHERE id=?`, ac.UserID).Scan(&version, &generation); err != nil {
		return ConfigSnapshot{}, err
	}
	mappings, err := a.ListMappings(ctx, ac.UserID)
	if err != nil {
		return ConfigSnapshot{}, err
	}
	domains, _ := a.ListDomains(ctx, ac.UserID)
	domainMap := make(map[string][]string)
	for _, domain := range domains {
		if domain.Status != "deleting" {
			domainMap[domain.MappingID] = append(domainMap[domain.MappingID], domain.Normalized)
		}
	}
	items := make([]map[string]interface{}, 0, len(mappings))
	for _, item := range mappings {
		if item.LifecycleStatus == "deleting" || item.DesiredState == "disabled" {
			continue
		}
		items = append(items, map[string]interface{}{"mapping_id": item.ID, "name": item.Name, "proxy_type": item.ProxyType, "local_ip": item.LocalIP, "local_port": item.LocalPort, "remote_port": item.RemotePort, "revision": item.Revision, "custom_domains": domainMap[item.ID]})
	}
	payload := map[string]interface{}{"frps_public_host": a.Config.FRPSPublicHost, "frps_public_port": a.Config.FRPSPublicPort, "mappings": items, "transport_secret_ref": "runtime-only"}
	now := time.Now().UTC()
	expires := now.Add(5 * time.Minute)
	snapshot := ConfigSnapshot{SchemaVersion: "v1", ConfigVersion: version, UserID: ac.UserID, SessionGeneration: generation, IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: expires.Format(time.RFC3339Nano), SigningKeyID: a.Crypto.KeyID, Payload: payload}
	unsigned, _ := json.Marshal(snapshot)
	hash := sha256.Sum256(unsigned)
	snapshot.ConfigHash = hex.EncodeToString(hash[:])
	unsigned, _ = json.Marshal(snapshot)
	snapshot.Signature = a.Crypto.Sign(unsigned)
	encoded, _ := json.Marshal(snapshot)
	_, _ = a.DB.ExecContext(ctx, `INSERT OR REPLACE INTO config_snapshots(id,user_id,version,schema_version,session_generation,config_json,config_hash,config_signing_key_id,config_signature,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, uuid.NewString(), ac.UserID, version, snapshot.SchemaVersion, generation, string(encoded), snapshot.ConfigHash, snapshot.SigningKeyID, snapshot.Signature, nowString())
	return snapshot, nil
}

func (a *App) ApplyResult(ctx context.Context, ac AuthContext, req ApplyResultRequest) error {
	if req.Status != "succeeded" && req.Status != "failed" {
		return fmt.Errorf("invalid apply status")
	}
	now := nowString()
	if req.Status == "succeeded" {
		tx, err := a.DB.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE mapping_revisions SET status='superseded' WHERE mapping_id IN (SELECT id FROM mappings WHERE user_id=?) AND status='active'`, ac.UserID); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE mapping_revisions SET status='active',applied_at=? WHERE mapping_id IN (SELECT id FROM mappings WHERE user_id=?) AND status IN ('pending','applying')`, now, ac.UserID); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE mappings SET active_revision_id=COALESCE(pending_revision_id,active_revision_id),pending_revision_id=NULL,lifecycle_status=CASE WHEN desired_state='disabled' THEN 'disabled' WHEN lifecycle_status='deleting' THEN 'deleting' ELSE 'running' END,observed_state='running',updated_at=? WHERE user_id=? AND lifecycle_status <> 'deleted'`, now, ac.UserID); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM port_leases WHERE mapping_id IN (SELECT id FROM mappings WHERE user_id=?) AND lease_role='pending'`, ac.UserID); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE port_leases SET lease_role='active' WHERE mapping_id IN (SELECT id FROM mappings WHERE user_id=?)`, ac.UserID); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM mappings WHERE user_id=? AND lifecycle_status='deleting'`, ac.UserID); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE users SET applied_config_version=?,last_failed_config_version=NULL,updated_at=? WHERE id=?`, req.ConfigVersion, now, ac.UserID); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE user_runtime_state SET observed_client_status='online',client_panel_version=?,frpc_version=?,last_heartbeat_at=?,last_applied_config_version=?,last_error_code=NULL,last_error_message=NULL,updated_at=? WHERE user_id=?`, req.ClientPanelVersion, req.FRPCVersion, now, req.ConfigVersion, now, ac.UserID); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		return a.Audit(ctx, ac, "config_apply_succeeded", "config", fmt.Sprint(req.ConfigVersion), "success", map[string]interface{}{"config_version": req.ConfigVersion}, "")
	}
	_, err := a.DB.ExecContext(ctx, `UPDATE users SET last_failed_config_version=?,updated_at=? WHERE id=?`, req.ConfigVersion, now, ac.UserID)
	if err == nil {
		_, _ = a.DB.ExecContext(ctx, `UPDATE mappings SET lifecycle_status='config_error',observed_state='offline',updated_at=? WHERE user_id=? AND lifecycle_status NOT IN ('deleted','disabled','deleting')`, now, ac.UserID)
		_, _ = a.DB.ExecContext(ctx, `UPDATE user_runtime_state SET observed_client_status='online',last_error_code=?,last_error_message=?,updated_at=? WHERE user_id=?`, req.ErrorCode, safeError(req.ErrorMessage), now, ac.UserID)
		_ = a.Audit(ctx, ac, "config_apply_failed", "config", fmt.Sprint(req.ConfigVersion), "failure", map[string]interface{}{"error_code": req.ErrorCode}, "")
	}
	return err
}

func (a *App) Heartbeat(ctx context.Context, ac AuthContext, clientVersion, frpcVersion string) error {
	now := nowString()
	_, err := a.DB.ExecContext(ctx, `UPDATE user_runtime_state SET observed_client_status='online',client_panel_version=?,frpc_version=?,last_heartbeat_at=?,updated_at=? WHERE user_id=?`, clientVersion, frpcVersion, now, now, ac.UserID)
	return err
}

func (a *App) AdminUsers(ctx context.Context) ([]UserRecord, error) {
	rows, err := a.DB.QueryContext(ctx, `SELECT id,username,role,status,must_change_password,created_at,desired_config_version,applied_config_version,active_session_generation FROM users WHERE status <> 'deleted' ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]UserRecord, 0)
	for rows.Next() {
		var item UserRecord
		var must int
		if err := rows.Scan(&item.ID, &item.Username, &item.Role, &item.Status, &must, &item.CreatedAt, &item.DesiredConfig, &item.AppliedConfig, &item.ActiveSessionGen); err != nil {
			return nil, err
		}
		item.MustChangePassword = must == 1
		result = append(result, item)
	}
	return result, rows.Err()
}

func (a *App) CreateUser(ctx context.Context, ac AuthContext, username string) (UserRecord, string, error) {
	username = strings.TrimSpace(username)
	if !validUsername(username) || username == "admin" {
		return UserRecord{}, "", fmt.Errorf("invalid username")
	}
	password, err := config.GenerateInitialPassword()
	if err != nil {
		return UserRecord{}, "", err
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return UserRecord{}, "", err
	}
	userID := uuid.NewString()
	secret, err := randomSecret()
	if err != nil {
		return UserRecord{}, "", err
	}
	ciphertext, nonce, err := a.Crypto.Encrypt([]byte(secret), "user:"+userID+":frp_secret:v1")
	if err != nil {
		return UserRecord{}, "", err
	}
	now := nowString()
	_, err = a.DB.ExecContext(ctx, `INSERT INTO users(id,username,password_hash,role,status,must_change_password,active_session_generation,created_at,updated_at) VALUES(?,?,?,'user','active',1,0,?,?)`, userID, username, hash, now, now)
	if err != nil {
		return UserRecord{}, "", err
	}
	_, err = a.DB.ExecContext(ctx, `INSERT INTO frp_credentials(id,user_id,frp_username,secret_hash,secret_ciphertext,secret_nonce,created_at) VALUES(?,?,?,?,?,?,?)`, uuid.NewString(), userID, "user-"+shortID(userID), sha256Hex(secret), ciphertext, nonce, now)
	if err != nil {
		return UserRecord{}, "", err
	}
	_ = a.Audit(ctx, ac, "user_created", "user", userID, "success", map[string]interface{}{"username": username}, "")
	return UserRecord{UserSummary: UserSummary{ID: userID, Username: username, Role: "user", Status: "active", MustChangePassword: true}, CreatedAt: now}, password, nil
}

func (a *App) SetUserStatus(ctx context.Context, ac AuthContext, userID, status string) error {
	if status != "active" && status != "disabled" {
		return fmt.Errorf("invalid user status")
	}
	result, err := a.DB.ExecContext(ctx, `UPDATE users SET status=?,active_session_generation=active_session_generation+1,updated_at=? WHERE id=? AND role='user'`, status, nowString(), userID)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if status == "disabled" {
		_, _ = a.DB.ExecContext(ctx, `UPDATE sessions SET revoked_at=?,revoke_reason='USER_DISABLED' WHERE user_id=? AND revoked_at IS NULL`, nowString(), userID)
		_, _ = a.DB.ExecContext(ctx, `UPDATE frp_runtime_credentials SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL`, nowString(), userID)
	}
	return a.Audit(ctx, ac, "user_status_changed", "user", userID, "success", map[string]interface{}{"status": status}, "")
}

func (a *App) ResetUserPassword(ctx context.Context, ac AuthContext, userID string) (string, error) {
	password, err := config.GenerateInitialPassword()
	if err != nil {
		return "", err
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return "", err
	}
	result, err := a.DB.ExecContext(ctx, `UPDATE users SET password_hash=?,must_change_password=1,auth_version=auth_version+1,active_session_generation=active_session_generation+1,updated_at=? WHERE id=? AND role='user'`, hash, nowString(), userID)
	if err != nil {
		return "", err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return "", ErrNotFound
	}
	_, _ = a.DB.ExecContext(ctx, `UPDATE sessions SET revoked_at=?,revoke_reason='PASSWORD_RESET' WHERE user_id=? AND revoked_at IS NULL`, nowString(), userID)
	_, _ = a.DB.ExecContext(ctx, `UPDATE frp_runtime_credentials SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL`, nowString(), userID)
	_ = a.Audit(ctx, ac, "user_password_reset", "user", userID, "success", nil, "")
	return password, nil
}

func (a *App) CloudflareStatus(ctx context.Context, userID string) (map[string]interface{}, error) {
	var status string
	var version int
	var verified string
	err := a.DB.QueryRowContext(ctx, `SELECT status,token_version,COALESCE(verified_at,'') FROM cloudflare_credentials WHERE user_id=? AND status <> 'retired' ORDER BY token_version DESC LIMIT 1`, userID).Scan(&status, &version, &verified)
	if errors.Is(err, sql.ErrNoRows) {
		return map[string]interface{}{"configured": false, "status": "missing"}, nil
	}
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"configured": true, "status": status, "token_version": version, "verified_at": verified}, nil
}

func (a *App) SaveCloudflareToken(ctx context.Context, ac AuthContext, token string) error {
	if len(strings.TrimSpace(token)) < 20 {
		return fmt.Errorf("cloudflare token is too short")
	}
	var next int
	_ = a.DB.QueryRowContext(ctx, `SELECT COALESCE(MAX(token_version),0)+1 FROM cloudflare_credentials WHERE user_id=?`, ac.UserID).Scan(&next)
	ciphertext, nonce, err := a.Crypto.Encrypt([]byte(token), "user:"+ac.UserID+":cloudflare_token:v1")
	if err != nil {
		return err
	}
	now := nowString()
	// Keep the previous active credential until the new pending version has
	// completed capability verification. A failed replacement must not take a
	// working DNS integration offline.
	_, err = a.DB.ExecContext(ctx, `INSERT INTO cloudflare_credentials(id,user_id,token_version,ciphertext,nonce,status,capabilities_json,created_at) VALUES(?,?,?,?,?,'pending','{}',?)`, uuid.NewString(), ac.UserID, next, ciphertext, nonce, now)
	if err == nil {
		_ = a.Audit(ctx, ac, "cloudflare_token_uploaded", "cloudflare_token", fmt.Sprint(next), "pending", nil, "")
	}
	return err
}

func (a *App) ClearCloudflareToken(ctx context.Context, ac AuthContext) error {
	_, err := a.DB.ExecContext(ctx, `UPDATE cloudflare_credentials SET status='retired',retired_at=? WHERE user_id=? AND status <> 'retired'`, nowString(), ac.UserID)
	if err == nil {
		_ = a.Audit(ctx, ac, "cloudflare_token_cleared", "cloudflare_token", ac.UserID, "success", nil, "")
	}
	return err
}

// AuthorizeFRP is the fail-closed boundary used by the FRPS plugin. It intentionally
// checks the session generation and mapping revision on every operation, so a transport
// secret alone can never create a user proxy.
func (a *App) AuthorizeFRP(ctx context.Context, operation, frpUsername, runtimeCredential string, generation int64, mappingID string, mappingRevision int64, remotePort int, hostname string) (bool, string, string) {
	var userID, status string
	var currentGeneration, sessionGeneration int64
	var expires string
	if err := a.DB.QueryRowContext(ctx, `SELECT u.id,u.status,u.active_session_generation,s.session_generation,rc.expires_at FROM frp_credentials fc JOIN users u ON u.id=fc.user_id JOIN frp_runtime_credentials rc ON rc.user_id=u.id JOIN sessions s ON s.id=rc.server_session_id WHERE fc.frp_username=? AND rc.token_hash=? AND rc.revoked_at IS NULL AND s.revoked_at IS NULL`, frpUsername, sha256Hex(runtimeCredential)).Scan(&userID, &status, &currentGeneration, &sessionGeneration, &expires); err != nil {
		return false, "FRP_RUNTIME_CREDENTIAL_INVALID", "FRP runtime credential is invalid."
	}
	if status != "active" {
		return false, "AUTH_USER_DISABLED", "User is not active."
	}
	if currentGeneration != generation || sessionGeneration != generation {
		return false, "SESSION_GENERATION_MISMATCH", "Session generation is stale."
	}
	expiresAt, _ := time.Parse(time.RFC3339Nano, expires)
	if time.Now().UTC().After(expiresAt) {
		return false, "SESSION_EXPIRED", "Runtime credential has expired."
	}
	if operation == "Login" || operation == "Ping" || operation == "NewWorkConn" || operation == "NewUserConn" {
		return true, "", ""
	}
	if operation != "NewProxy" {
		return false, "FRP_OPERATION_NOT_ALLOWED", "FRP operation is not allowed."
	}
	var owner, lifecycle, desired, proxyType string
	var revision int64
	var authorizedPort *int
	if err := a.DB.QueryRowContext(ctx, `SELECT m.user_id,m.lifecycle_status,m.desired_state,m.proxy_type,r.revision,r.remote_port FROM mappings m JOIN mapping_revisions r ON r.id=COALESCE(m.pending_revision_id,m.active_revision_id) WHERE m.id=?`, mappingID).Scan(&owner, &lifecycle, &desired, &proxyType, &revision, &authorizedPort); err != nil {
		return false, "MAPPING_NOT_FOUND", "Mapping is not available."
	}
	if owner != userID || desired == "disabled" || lifecycle == "disabled" || lifecycle == "deleting" || lifecycle == "deleted" {
		return false, "MAPPING_NOT_AUTHORIZED", "Mapping is not authorized."
	}
	if revision != mappingRevision {
		return false, "RESOURCE_REVISION_CONFLICT", "Mapping revision is stale."
	}
	if authorizedPort != nil && remotePort != *authorizedPort {
		return false, "PORT_NOT_ALLOWED", "Remote port is not authorized."
	}
	if hostname != "" {
		normalizedHostname, normalizeErr := normalizeDomain(hostname)
		if normalizeErr != nil {
			return false, "DOMAIN_NOT_AUTHORIZED", "Hostname is not authorized."
		}
		var domainOwner, domainStatus string
		if err := a.DB.QueryRowContext(ctx, `SELECT user_id,status FROM domain_bindings WHERE normalized_domain=?`, normalizedHostname).Scan(&domainOwner, &domainStatus); err != nil || domainOwner != userID || domainStatus == "deleted" {
			return false, "DOMAIN_NOT_AUTHORIZED", "Hostname is not authorized."
		}
	}
	if proxyType == "http" && hostname == "" {
		return false, "DOMAIN_REQUIRED", "HTTP mapping requires an authorized hostname."
	}
	return true, "", ""
}

func (a *App) Operations(ctx context.Context, userID string, admin bool) ([]map[string]interface{}, error) {
	query := `SELECT id,COALESCE(user_id,''),resource_type,COALESCE(resource_id,''),operation_type,status,phase,step,COALESCE(error_code,''),COALESCE(error_message,''),created_at,updated_at FROM operations`
	args := []interface{}{}
	if !admin {
		query += ` WHERE user_id=?`
		args = append(args, userID)
	}
	query += ` ORDER BY created_at DESC LIMIT 100`
	rows, err := a.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]map[string]interface{}, 0)
	for rows.Next() {
		var id, owner, resourceType, resourceID, opType, status, phase, step, code, message, created, updated string
		if err := rows.Scan(&id, &owner, &resourceType, &resourceID, &opType, &status, &phase, &step, &code, &message, &created, &updated); err != nil {
			return nil, err
		}
		result = append(result, map[string]interface{}{"id": id, "user_id": owner, "resource_type": resourceType, "resource_id": resourceID, "operation_type": opType, "status": status, "phase": phase, "step": step, "error_code": code, "error_message": message, "created_at": created, "updated_at": updated})
	}
	return result, rows.Err()
}

func (a *App) Audit(ctx context.Context, ac AuthContext, action, resourceType, resourceID, result string, metadata map[string]interface{}, operationID string) error {
	if metadata == nil {
		metadata = map[string]interface{}{}
	}
	for key := range metadata {
		if !allowedAuditField(key) {
			delete(metadata, key)
		}
	}
	encoded, _ := json.Marshal(metadata)
	_, err := a.DB.ExecContext(ctx, `INSERT INTO audit_logs(id,actor_type,actor_id,server_session_id,session_generation,source_ip,user_agent,request_id,operation_id,action,resource_type,resource_id,result,metadata_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, uuid.NewString(), ac.Role, ac.UserID, ac.SessionID, ac.Generation, "", "", uuid.NewString(), nullableString(operationID), action, nullableString(resourceType), nullableString(resourceID), result, string(encoded), nowString())
	return err
}

func allocatePort(ctx context.Context, tx *sql.Tx, start, end int) (int, error) {
	for port := start; port <= end; port++ {
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM port_leases WHERE server_id='default' AND remote_port=?`, port).Scan(&count); err != nil {
			return 0, err
		}
		if count == 0 {
			return port, nil
		}
	}
	return 0, fmt.Errorf("no allocatable port")
}

func validateMapping(req MappingRequest) error {
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$`).MatchString(strings.TrimSpace(req.Name)) {
		return fmt.Errorf("invalid mapping name")
	}
	if req.ProxyType != "tcp" && req.ProxyType != "udp" && req.ProxyType != "http" {
		return fmt.Errorf("unsupported proxy type")
	}
	if net.ParseIP(req.LocalIP) == nil && !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$`).MatchString(req.LocalIP) {
		return fmt.Errorf("invalid local_ip")
	}
	if req.LocalPort < 1 || req.LocalPort > 65535 {
		return fmt.Errorf("invalid local_port")
	}
	if req.RemotePort != nil && (*req.RemotePort < 0 || *req.RemotePort > 65535) {
		return fmt.Errorf("invalid remote_port")
	}
	return nil
}

func normalizeDomain(raw string) (string, error) {
	raw = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if raw == "" || len(raw) > 253 || strings.ContainsAny(raw, "/*\\") {
		return "", fmt.Errorf("invalid domain")
	}
	ascii, err := idna.Lookup.ToASCII(raw)
	if err != nil {
		return "", fmt.Errorf("invalid IDNA domain")
	}
	labels := strings.Split(ascii, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("domain must contain a registrable suffix")
	}
	for _, label := range labels {
		if len(label) < 1 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", fmt.Errorf("invalid DNS label")
		}
	}
	return ascii, nil
}

func requestHash(value interface{}) string {
	encoded, _ := json.Marshal(value)
	return sha256Hex(string(encoded))
}
func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
func randomToken() (string, error) { return randomSecret() }
func randomSecret() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func nowString() string { return time.Now().UTC().Format(time.RFC3339Nano) }
func nullablePort(port *int) interface{} {
	if port == nil {
		return nil
	}
	return *port
}
func nullableString(value string) interface{} {
	if value == "" {
		return nil
	}
	return value
}
func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
func shortID(value string) string {
	value = strings.ReplaceAll(value, "-", "")
	if len(value) > 12 {
		return value[:12]
	}
	return value
}
func safeError(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 240 {
		return value[:240]
	}
	return value
}
func validUsername(value string) bool {
	return regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9._-]{2,39}$`).MatchString(value)
}
func allowedAuditField(value string) bool {
	switch value {
	case "proxy_type", "revision", "enabled", "status", "username", "config_version", "error_code":
		return true
	default:
		return false
	}
}
func osWritePrivate(path string, content []byte) error { return writePrivate(path, content) }

// The indirection keeps secret-file creation in one audited helper and makes it easy to replace with an OS secret store.
func writePrivate(path string, content []byte) error { return os.WriteFile(path, content, 0o600) }
