package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ricardo/frp-panel-platform/server/internal/router"
)

type RouterStatus struct {
	ConfigVersion     int64  `json:"router_config_version"`
	AppliedVersion    int64  `json:"router_applied_version"`
	LastGoodVersion   *int64 `json:"last_good_snapshot_version,omitempty"`
	LastGoodPath      string `json:"last_good_snapshot_path,omitempty"`
	LastGoodHash      string `json:"last_good_snapshot_hash,omitempty"`
	LastApplyError    string `json:"last_router_apply_error,omitempty"`
	SnapshotDirectory string `json:"snapshot_directory"`
	Adapter           string `json:"adapter"`
}

// EnqueueRouterSnapshot schedules a single deduplicated rebuild. The job
// reads the database before writing a snapshot and never exposes the DB to a
// Router process.
func (a *App) EnqueueRouterSnapshot(ctx context.Context) error {
	if a.Jobs == nil {
		return errors.New("job worker is unavailable")
	}
	_, err := a.Jobs.Enqueue(ctx, "router_snapshot_apply", "router", "singleton", "router:snapshot", map[string]interface{}{}, nil)
	return err
}

func (a *App) RouterStatus(ctx context.Context) (RouterStatus, error) {
	var status RouterStatus
	var lastGood sql.NullInt64
	err := a.DB.QueryRowContext(ctx, `SELECT router_config_version,router_applied_version,last_good_snapshot_version,COALESCE(last_good_snapshot_path,''),COALESCE(last_good_snapshot_hash,''),COALESCE(last_router_apply_error,'') FROM router_state WHERE singleton_id=1`).Scan(&status.ConfigVersion, &status.AppliedVersion, &lastGood, &status.LastGoodPath, &status.LastGoodHash, &status.LastApplyError)
	if err != nil {
		return status, err
	}
	if lastGood.Valid {
		status.LastGoodVersion = &lastGood.Int64
	}
	status.SnapshotDirectory = a.routerSnapshotDir()
	status.Adapter = "file-last-good"
	return status, nil
}

type routeSource struct {
	domainID      string
	hostname      string
	httpsMode     string
	redirect      bool
	mappingStatus string
	domainStatus  string
}

// BuildRouterSnapshot is the Control-side adapter. It emits a signed,
// versioned snapshot and atomically promotes it as last-good only after the
// file can be parsed and its HMAC verifies. A real Router can consume the same
// file and acknowledge the version over its local IPC channel.
func (a *App) BuildRouterSnapshot(ctx context.Context) (router.Snapshot, error) {
	if len(a.Crypto.RouterKey) != 32 {
		return router.Snapshot{}, errors.New("router snapshot key is unavailable")
	}
	rows, err := a.DB.QueryContext(ctx, `SELECT d.id,d.normalized_domain,d.https_mode,d.http_redirect,m.lifecycle_status,d.status FROM domain_bindings d JOIN mappings m ON m.id=d.mapping_id WHERE d.status NOT IN ('deleted','deleting','dns_error') ORDER BY d.normalized_domain`)
	if err != nil {
		return router.Snapshot{}, err
	}
	defer rows.Close()
	sources := make([]routeSource, 0)
	for rows.Next() {
		var item routeSource
		var redirect int
		if err := rows.Scan(&item.domainID, &item.hostname, &item.httpsMode, &redirect, &item.mappingStatus, &item.domainStatus); err != nil {
			return router.Snapshot{}, err
		}
		item.redirect = redirect == 1
		sources = append(sources, item)
	}
	if err := rows.Err(); err != nil {
		return router.Snapshot{}, err
	}

	var current int64
	if err := a.DB.QueryRowContext(ctx, `SELECT router_config_version FROM router_state WHERE singleton_id=1`).Scan(&current); err != nil {
		return router.Snapshot{}, err
	}
	control := make([]router.Route, 0, len(a.Config.RouterControlHosts))
	for _, hostname := range a.Config.RouterControlHosts {
		control = append(control, router.Route{Hostname: hostname, Target: a.Config.RouterControlTarget, HTTPSMode: "control", Status: "active"})
	}
	business := make([]router.Route, 0, len(sources))
	for _, source := range sources {
		status := "offline"
		if source.mappingStatus == "running" {
			status = "active"
		}
		business = append(business, router.Route{Hostname: source.hostname, Target: a.Config.RouterBusinessTarget, HTTPSMode: source.httpsMode, HTTPRedirect: source.redirect, Status: status})
	}
	snapshot, err := router.Build(current+1, control, business, a.Crypto.RouterKey)
	if err != nil {
		return router.Snapshot{}, err
	}
	snapshotDir := a.routerSnapshotDir()
	if err := os.MkdirAll(snapshotDir, 0o700); err != nil {
		return router.Snapshot{}, err
	}
	path := filepath.Join(snapshotDir, fmt.Sprintf("snapshot-v%d.json", snapshot.Version))
	if err := router.AtomicWrite(path, snapshot); err != nil {
		return router.Snapshot{}, err
	}
	if !router.Verify(snapshot, a.Crypto.RouterKey) {
		return router.Snapshot{}, errors.New("router snapshot self-verification failed")
	}
	now := nowString()
	if _, err := a.DB.ExecContext(ctx, `UPDATE router_snapshots SET status='superseded' WHERE status IN ('pending','applying','active')`); err != nil {
		return router.Snapshot{}, err
	}
	if _, err := a.DB.ExecContext(ctx, `INSERT INTO router_snapshots(version,schema_version,snapshot_path,snapshot_hash,snapshot_hmac,status,generated_at,applied_at) VALUES(?,?,?,?,?,'active',?,?)`, snapshot.Version, snapshot.SchemaVersion, path, snapshot.Hash, snapshot.HMAC, now, now); err != nil {
		return router.Snapshot{}, err
	}
	if _, err := a.DB.ExecContext(ctx, `UPDATE router_state SET router_config_version=?,router_applied_version=?,last_good_snapshot_version=?,last_good_snapshot_path=?,last_good_snapshot_hash=?,last_router_apply_error=NULL,updated_at=? WHERE singleton_id=1`, snapshot.Version, snapshot.Version, snapshot.Version, path, snapshot.Hash, now); err != nil {
		return router.Snapshot{}, err
	}
	if err := a.finalizeDomainRouterStates(ctx, sources, snapshot.Version); err != nil {
		return router.Snapshot{}, err
	}
	return snapshot, nil
}

func (a *App) routerSnapshotDir() string {
	if a.Config.RouterSnapshotDir != "" {
		return a.Config.RouterSnapshotDir
	}
	return filepath.Join(a.Config.DataDir, "router")
}

func (a *App) finalizeDomainRouterStates(ctx context.Context, sources []routeSource, version int64) error {
	now := nowString()
	for _, source := range sources {
		if source.domainStatus == "pending_dns" {
			continue
		}
		domainStatus := "pending_client"
		operationStatus := "running"
		phase, step := "client", "awaiting_apply"
		if source.domainStatus == "pending_certificate" && source.httpsMode != "http_only" {
			domainStatus, phase, step = "pending_certificate", "certificate", "awaiting_valid_certificate"
		} else if source.mappingStatus == "running" {
			if source.httpsMode == "http_only" {
				domainStatus, operationStatus, phase, step = "active", "succeeded", "router", "applied"
			} else {
				var certificateStatus string
				err := a.DB.QueryRowContext(ctx, `SELECT status FROM certificates WHERE domain_binding_id=? AND provider='acme'`, source.domainID).Scan(&certificateStatus)
				if err == nil && certificateStatus == "valid" {
					domainStatus, operationStatus, phase, step = "active", "succeeded", "router", "applied"
				} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
					return err
				} else if certificateStatus == "error" || certificateStatus == "expired" {
					domainStatus, operationStatus, phase, step = "certificate_error", "failed", "certificate", "failed"
				} else {
					domainStatus, phase, step = "pending_certificate", "certificate", "awaiting_valid_certificate"
				}
			}
		}
		if _, err := a.DB.ExecContext(ctx, `UPDATE domain_bindings SET status=?,updated_at=? WHERE id=?`, domainStatus, now, source.domainID); err != nil {
			return err
		}
		if _, err := a.DB.ExecContext(ctx, `UPDATE operations SET status=?,phase=?,step=?,updated_at=?,completed_at=CASE WHEN ?='succeeded' THEN ? ELSE completed_at END WHERE resource_type='domain' AND resource_id=? AND status IN ('pending','running')`, operationStatus, phase, step, now, operationStatus, now, source.domainID); err != nil {
			return err
		}
	}
	_ = version
	return nil
}
