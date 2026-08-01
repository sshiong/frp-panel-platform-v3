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
