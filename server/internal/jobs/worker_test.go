package jobs

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/ricardo/frp-panel-platform/server/internal/db"
)

func TestEnqueueClaimLeaseRetryAndDeduplication(t *testing.T) {
	database, err := db.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store := New(database, "test-worker")
	store.Lease = time.Second
	store.RetryBase = time.Millisecond
	ctx := context.Background()
	first, err := store.Enqueue(ctx, "dns_sync", "domain", "domain-1", "domain-1:dns", map[string]interface{}{"domain_id": "domain-1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Enqueue(ctx, "dns_sync", "domain", "domain-1", "domain-1:dns", nil, nil)
	if err != nil || first != second {
		t.Fatalf("deduplication: %q %q %v", first, second, err)
	}
	if _, err := database.ExecContext(ctx, `UPDATE jobs SET run_after=? WHERE id=?`, time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano), first); err != nil {
		t.Fatal(err)
	}
	claimed, err := store.Claim(ctx)
	if err != nil || claimed.ID != first || claimed.Attempts != 1 || claimed.Payload["domain_id"] != "domain-1" {
		t.Fatalf("claim: %#v %v", claimed, err)
	}
	if err := store.Heartbeat(ctx, claimed.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.Fail(ctx, claimed.ID, errors.New("temporary")); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := database.QueryRowContext(ctx, `SELECT status FROM jobs WHERE id=?`, claimed.ID).Scan(&status); err != nil || status != "retry_wait" {
		t.Fatalf("retry status: %q %v", status, err)
	}
	if _, err := database.ExecContext(ctx, `UPDATE jobs SET run_after=? WHERE id=?`, time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano), claimed.ID); err != nil {
		t.Fatal(err)
	}
	claimed, err = store.Claim(ctx)
	if err != nil || claimed.Attempts != 2 {
		t.Fatalf("reclaim: %#v %v", claimed, err)
	}
	if err := store.Complete(ctx, claimed.ID); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, `SELECT status FROM jobs WHERE id=?`, claimed.ID).Scan(&status); err != nil || status != "succeeded" {
		t.Fatalf("complete status: %q %v", status, err)
	}
}

func TestWorkerFailureAndLifecycleEdges(t *testing.T) {
	database, err := db.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	ctx := context.Background()
	store := New(database, "edge-worker")
	store.Lease = 20 * time.Millisecond
	store.RetryBase = time.Millisecond

	if _, err := store.Claim(ctx); !errors.Is(err, ErrNoJob) {
		t.Fatalf("empty queue claim error=%v", err)
	}
	if _, err := store.Enqueue(ctx, "", "domain", "1", "", nil, nil); err == nil {
		t.Fatal("empty job type was accepted")
	}
	if _, err := store.Enqueue(ctx, "job", "", "1", "", nil, nil); err == nil {
		t.Fatal("empty resource type was accepted")
	}
	if _, err := store.Enqueue(ctx, "job", "domain", "1", "", map[string]interface{}{"function": func() {}}, nil); err == nil {
		t.Fatal("non-JSON job payload was accepted")
	}

	version := int64(7)
	jobID, err := store.Enqueue(ctx, "token", "user", "user-1", "", map[string]interface{}{"ok": true}, &version)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := store.Claim(ctx)
	if err != nil || claimed.TokenVersion == nil || *claimed.TokenVersion != version {
		t.Fatalf("token version claim=%#v err=%v", claimed, err)
	}
	if err := store.Complete(ctx, "missing-job"); err == nil {
		t.Fatal("completing an unknown job was accepted")
	}
	if err := store.Block(ctx, claimed.ID, nil); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := database.QueryRowContext(ctx, `SELECT status FROM jobs WHERE id=?`, jobID).Scan(&status); err != nil || status != "retry_wait" {
		t.Fatalf("blocked job status=%q err=%v", status, err)
	}
	if err := store.Heartbeat(ctx, claimed.ID); err != nil {
		t.Fatal(err)
	}

	failureID, err := store.Enqueue(ctx, "failure", "domain", "domain-1", "failure:1", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	failedJob, err := store.Claim(ctx)
	if err != nil || failedJob.ID != failureID {
		t.Fatalf("failure claim=%#v err=%v", failedJob, err)
	}
	if _, err := database.ExecContext(ctx, `UPDATE jobs SET max_attempts=1 WHERE id=?`, failureID); err != nil {
		t.Fatal(err)
	}
	if err := store.Fail(ctx, failureID, errors.New(string(make([]byte, 700)))); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, `SELECT status,last_error FROM jobs WHERE id=?`, failureID).Scan(&status, new(string)); err != nil || status != "failed" {
		t.Fatalf("terminal failure status=%q err=%v", status, err)
	}
	if err := store.Complete(ctx, failureID); err == nil {
		t.Fatal("completed failed job without a lease")
	}

	malformedID, err := store.Enqueue(ctx, "malformed", "domain", "domain-2", "malformed:1", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `UPDATE jobs SET payload_json=? WHERE id=?`, "{", malformedID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Claim(ctx); err == nil {
		t.Fatal("malformed payload was accepted")
	}
	if err := database.QueryRowContext(ctx, `SELECT status FROM jobs WHERE id=?`, malformedID).Scan(&status); err != nil || status != "failed" {
		t.Fatalf("malformed payload status=%q err=%v", status, err)
	}

	blockedID, err := store.Enqueue(ctx, "blocked", "domain", "domain-3", "blocked:1", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.runOnce(ctx, func(context.Context, Job) error { return &BlockedError{Err: errors.New("waiting")} }); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, `SELECT status FROM jobs WHERE id=?`, blockedID).Scan(&status); err != nil || status != "retry_wait" {
		t.Fatalf("runOnce blocked status=%q err=%v", status, err)
	}

	runFailureID, err := store.Enqueue(ctx, "run-failure", "domain", "domain-4", "run-failure:1", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.runOnce(ctx, func(context.Context, Job) error { return errors.New("temporary failure") }); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, `SELECT status FROM jobs WHERE id=?`, runFailureID).Scan(&status); err != nil || status != "retry_wait" {
		t.Fatalf("runOnce failure status=%q err=%v", status, err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	cancel()
	if err := store.Run(runCtx, 0, func(context.Context, Job) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled worker run error=%v", err)
	}
	if err := store.Run(ctx, time.Millisecond, nil); err == nil {
		t.Fatal("nil worker handler was accepted")
	}
}

func TestRunHeartbeatKeepsLongJobLeased(t *testing.T) {
	database, err := db.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store := New(database, "heartbeat-worker")
	store.Lease = 30 * time.Millisecond
	store.RetryBase = time.Millisecond
	jobID, err := store.Enqueue(context.Background(), "slow", "test", "1", "slow:1", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.runOnce(context.Background(), func(context.Context, Job) error {
		time.Sleep(90 * time.Millisecond)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := database.QueryRow(`SELECT status FROM jobs WHERE id=?`, jobID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "succeeded" {
		t.Fatalf("long job status = %q", status)
	}
}
