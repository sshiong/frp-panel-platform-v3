package jobs

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/ricardo/frp-panel-platform/server/internal/db"
)

var ErrNoJob = errors.New("no due job")

// BlockedError keeps a job retryable without consuming its finite retry
// budget. It is used for missing external prerequisites such as an ACME
// account or a verified Cloudflare token.
type BlockedError struct{ Err error }

func (e *BlockedError) Error() string {
	if e == nil || e.Err == nil {
		return "job is blocked"
	}
	return e.Err.Error()
}

func (e *BlockedError) Unwrap() error { return e.Err }

type Job struct {
	ID               string
	Type             string
	ResourceType     string
	ResourceID       string
	Status           string
	RunAfter         time.Time
	Attempts         int
	MaxAttempts      int
	LockOwner        string
	LockExpiresAt    *time.Time
	DeduplicationKey string
	TokenVersion     *int64
	LastError        string
	Payload          map[string]interface{}
}

type Store struct {
	DB        *db.DB
	Owner     string
	Lease     time.Duration
	RetryBase time.Duration
}

func New(database *db.DB, owner string) *Store {
	if owner == "" {
		owner = uuid.NewString()
	}
	return &Store{DB: database, Owner: owner, Lease: 30 * time.Second, RetryBase: time.Second}
}

func (s *Store) Enqueue(ctx context.Context, jobType, resourceType, resourceID, deduplicationKey string, payload map[string]interface{}, tokenVersion *int64) (string, error) {
	if jobType == "" || resourceType == "" {
		return "", errors.New("job type and resource type are required")
	}
	if payload == nil {
		payload = map[string]interface{}{}
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	id := uuid.NewString()
	now := time.Now().UTC()
	_, err = s.DB.ExecContext(ctx, `INSERT OR IGNORE INTO jobs(id,type,resource_type,resource_id,status,run_after,attempts,max_attempts,deduplication_key,token_version,payload_json,created_at,updated_at) VALUES(?,?,?,?, 'pending', ?,0,5,?,?,?, ?, ?)`, id, jobType, resourceType, nullable(resourceID), now.Format(time.RFC3339Nano), nullable(deduplicationKey), tokenVersion, string(encoded), now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		return "", err
	}
	if deduplicationKey == "" {
		return id, nil
	}
	var existing string
	if err := s.DB.QueryRowContext(ctx, `SELECT id FROM jobs WHERE type=? AND deduplication_key=? AND status IN ('pending','running','retry_wait') ORDER BY created_at ASC LIMIT 1`, jobType, deduplicationKey).Scan(&existing); err != nil {
		return "", err
	}
	return existing, nil
}

func (s *Store) Claim(ctx context.Context) (Job, error) {
	now := time.Now().UTC()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Job{}, err
	}
	defer tx.Rollback()
	var job Job
	var resourceID, dedup, lastError, runAfter string
	var lockExpires sql.NullString
	var tokenVersion sql.NullInt64
	var payload string
	err = tx.QueryRowContext(ctx, `SELECT id,type,resource_type,COALESCE(resource_id,''),status,run_after,attempts,max_attempts,COALESCE(lock_owner,''),lock_expires_at,COALESCE(deduplication_key,''),token_version,COALESCE(last_error,''),payload_json FROM jobs WHERE status IN ('pending','retry_wait','running') AND run_after <= ? AND (lock_expires_at IS NULL OR lock_expires_at <= ?) ORDER BY run_after ASC,id ASC LIMIT 1`, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)).Scan(&job.ID, &job.Type, &job.ResourceType, &resourceID, &job.Status, &runAfter, &job.Attempts, &job.MaxAttempts, &job.LockOwner, &lockExpires, &dedup, &tokenVersion, &lastError, &payload)
	if errors.Is(err, sql.ErrNoRows) {
		return Job{}, ErrNoJob
	}
	if err != nil {
		return Job{}, err
	}
	expires := now.Add(s.Lease)
	result, err := tx.ExecContext(ctx, `UPDATE jobs SET status='running',attempts=attempts+1,lock_owner=?,locked_at=?,lock_expires_at=?,heartbeat_at=?,updated_at=? WHERE id=? AND status IN ('pending','retry_wait','running') AND (lock_expires_at IS NULL OR lock_expires_at <= ?)`, s.Owner, now.Format(time.RFC3339Nano), expires.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), job.ID, now.Format(time.RFC3339Nano))
	if err != nil {
		return Job{}, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return Job{}, ErrNoJob
	}
	if err := tx.Commit(); err != nil {
		return Job{}, err
	}
	job.ResourceID = resourceID
	job.Status = "running"
	job.RunAfter, _ = time.Parse(time.RFC3339Nano, runAfter)
	job.Attempts++
	job.LockOwner = s.Owner
	job.LockExpiresAt = &expires
	job.DeduplicationKey = dedup
	job.LastError = lastError
	if tokenVersion.Valid {
		v := tokenVersion.Int64
		job.TokenVersion = &v
	}
	job.Payload = map[string]interface{}{}
	if payload != "" {
		if err := json.Unmarshal([]byte(payload), &job.Payload); err != nil {
			return Job{}, fmt.Errorf("decode job payload: %w", err)
		}
	}
	return job, nil
}

func (s *Store) Heartbeat(ctx context.Context, id string) error {
	now := time.Now().UTC()
	_, err := s.DB.ExecContext(ctx, `UPDATE jobs SET heartbeat_at=?,lock_expires_at=?,updated_at=? WHERE id=? AND status='running' AND lock_owner=?`, now.Format(time.RFC3339Nano), now.Add(s.Lease).Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), id, s.Owner)
	return err
}

func (s *Store) Complete(ctx context.Context, id string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := s.DB.ExecContext(ctx, `UPDATE jobs SET status='succeeded',lock_owner=NULL,locked_at=NULL,lock_expires_at=NULL,heartbeat_at=NULL,completed_at=?,updated_at=? WHERE id=? AND status='running' AND lock_owner=?`, now, now, id, s.Owner)
	if err == nil {
		if affected, _ := result.RowsAffected(); affected != 1 {
			return errors.New("job lease lost")
		}
	}
	return err
}

func (s *Store) Fail(ctx context.Context, id string, jobErr error) error {
	if jobErr == nil {
		jobErr = errors.New("job failed")
	}
	var attempts, maxAttempts int
	if err := s.DB.QueryRowContext(ctx, `SELECT attempts,max_attempts FROM jobs WHERE id=? AND status='running' AND lock_owner=?`, id, s.Owner).Scan(&attempts, &maxAttempts); err != nil {
		return err
	}
	now := time.Now().UTC()
	message := jobErr.Error()
	if len(message) > 500 {
		message = message[:500]
	}
	if attempts >= maxAttempts {
		_, err := s.DB.ExecContext(ctx, `UPDATE jobs SET status='failed',last_error=?,lock_owner=NULL,lock_expires_at=NULL,heartbeat_at=NULL,completed_at=?,updated_at=? WHERE id=? AND lock_owner=?`, message, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), id, s.Owner)
		return err
	}
	seconds := math.Min(float64(300), math.Pow(2, float64(max(0, attempts-1))))
	runAfter := now.Add(time.Duration(seconds * float64(s.RetryBase)))
	_, err := s.DB.ExecContext(ctx, `UPDATE jobs SET status='retry_wait',run_after=?,last_error=?,lock_owner=NULL,lock_expires_at=NULL,heartbeat_at=NULL,updated_at=? WHERE id=? AND lock_owner=?`, runAfter.Format(time.RFC3339Nano), message, now.Format(time.RFC3339Nano), id, s.Owner)
	return err
}

func (s *Store) Block(ctx context.Context, id string, jobErr error) error {
	if jobErr == nil {
		jobErr = errors.New("job is blocked")
	}
	message := jobErr.Error()
	if len(message) > 500 {
		message = message[:500]
	}
	now := time.Now().UTC()
	// A blocked job remains visible and retryable, but does not hot-loop. The
	// operator can wake it through Retry or the next worker seed pass.
	wake := now.Add(24 * time.Hour)
	_, err := s.DB.ExecContext(ctx, `UPDATE jobs SET status='retry_wait',run_after=?,last_error=?,lock_owner=NULL,lock_expires_at=NULL,heartbeat_at=NULL,updated_at=? WHERE id=? AND status='running' AND lock_owner=?`, wake.Format(time.RFC3339Nano), message, now.Format(time.RFC3339Nano), id, s.Owner)
	return err
}

func (s *Store) Run(ctx context.Context, interval time.Duration, handler func(context.Context, Job) error) error {
	if interval <= 0 {
		interval = time.Second
	}
	if handler == nil {
		return errors.New("job handler is required")
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := s.runOnce(ctx, handler); err != nil && !errors.Is(err, ErrNoJob) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (s *Store) runOnce(ctx context.Context, handler func(context.Context, Job) error) error {
	job, err := s.Claim(ctx)
	if err != nil {
		return err
	}
	// External handlers may spend longer than one lease (for example while
	// waiting for ACME DNS propagation). Keep the lease alive independently
	// from the handler so a second worker cannot reclaim the same operation.
	heartbeatCtx, heartbeatCancel := context.WithCancel(ctx)
	heartbeatInterval := s.Lease / 3
	if heartbeatInterval <= 0 {
		heartbeatInterval = time.Second
	}
	heartbeatDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(heartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				_ = s.Heartbeat(heartbeatCtx, job.ID)
			case <-heartbeatCtx.Done():
				close(heartbeatDone)
				return
			}
		}
	}()
	defer func() {
		heartbeatCancel()
		<-heartbeatDone
	}()
	if err := handler(heartbeatCtx, job); err != nil {
		var blocked *BlockedError
		if errors.As(err, &blocked) {
			return s.Block(ctx, job.ID, blocked)
		}
		return s.Fail(ctx, job.ID, err)
	}
	return s.Complete(ctx, job.ID)
}

func nullable(value string) interface{} {
	if value == "" {
		return nil
	}
	return value
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
