package service

import (
	"context"
	"testing"
)

func TestApplyFailurePreservesActiveRevisionAndReleasesPendingPort(t *testing.T) {
	fixture := newServiceCoverageFixture(t)
	ctx := context.Background()
	app, client := fixture.app, fixture.client

	oldPort := 6300
	mapping, err := app.CreateMapping(ctx, client, MappingRequest{
		Name:       "revision-failure",
		ProxyType:  "tcp",
		LocalIP:    "127.0.0.1",
		LocalPort:  8300,
		RemotePort: &oldPort,
	}, "revision-failure-create-000001")
	if err != nil {
		t.Fatal(err)
	}
	initial, err := app.FullConfig(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.ApplyResult(ctx, client, ApplyResultRequest{Status: "succeeded", ConfigVersion: initial.ConfigVersion, ClientPanelVersion: "0.1.0", FRPCVersion: "0.68.0"}); err != nil {
		t.Fatal(err)
	}

	newPort := 6301
	updated, err := app.UpdateMapping(ctx, client, mapping.ID, MappingRequest{
		Name:       "revision-failure",
		ProxyType:  "tcp",
		LocalIP:    "127.0.0.1",
		LocalPort:  8301,
		RemotePort: &newPort,
	}, "revision-failure-update-000001")
	if err != nil {
		t.Fatal(err)
	}
	failedConfig, err := app.FullConfig(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	if failedConfig.ConfigVersion <= initial.ConfigVersion || updated.Revision != mapping.Revision+1 {
		t.Fatalf("unexpected pending revision/config version: revision=%d initial=%d config=%d", updated.Revision, mapping.Revision, failedConfig.ConfigVersion)
	}
	if err := app.ApplyResult(ctx, client, ApplyResultRequest{
		Status:             "failed",
		ConfigVersion:      failedConfig.ConfigVersion,
		ErrorCode:          "CONFIG_ERROR",
		ErrorMessage:       "new revision rejected",
		ClientPanelVersion: "0.1.0",
		FRPCVersion:        "0.68.0",
	}); err != nil {
		t.Fatal(err)
	}

	var lifecycle, observed, activeID, pendingID string
	if err := app.DB.QueryRowContext(ctx, `SELECT lifecycle_status,observed_state,COALESCE(active_revision_id,''),COALESCE(pending_revision_id,'') FROM mappings WHERE id=?`, mapping.ID).Scan(&lifecycle, &observed, &activeID, &pendingID); err != nil {
		t.Fatal(err)
	}
	if lifecycle != "config_error" || observed != "offline" || activeID == "" || pendingID != "" {
		t.Fatalf("failed revision changed mapping authority: lifecycle=%q observed=%q active=%q pending=%q", lifecycle, observed, activeID, pendingID)
	}

	var activeStatus, failedStatus string
	if err := app.DB.QueryRowContext(ctx, `SELECT status FROM mapping_revisions WHERE mapping_id=? AND revision=?`, mapping.ID, mapping.Revision).Scan(&activeStatus); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.QueryRowContext(ctx, `SELECT status FROM mapping_revisions WHERE mapping_id=? AND revision=?`, mapping.ID, updated.Revision).Scan(&failedStatus); err != nil {
		t.Fatal(err)
	}
	if activeStatus != "active" || failedStatus != "failed" {
		t.Fatalf("revision states after failed apply: active=%q failed=%q", activeStatus, failedStatus)
	}

	var oldLease, pendingLease int
	if err := app.DB.QueryRowContext(ctx, `SELECT COUNT(1) FROM port_leases WHERE mapping_id=? AND remote_port=?`, mapping.ID, oldPort).Scan(&oldLease); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.QueryRowContext(ctx, `SELECT COUNT(1) FROM port_leases WHERE mapping_id=? AND remote_port=?`, mapping.ID, newPort).Scan(&pendingLease); err != nil {
		t.Fatal(err)
	}
	if oldLease != 1 || pendingLease != 0 {
		t.Fatalf("port leases after failed apply: old=%d pending=%d", oldLease, pendingLease)
	}

	retryPort := 6302
	retry, err := app.UpdateMapping(ctx, client, mapping.ID, MappingRequest{
		Name:       "revision-failure-retry",
		ProxyType:  "tcp",
		LocalIP:    "127.0.0.1",
		LocalPort:  8302,
		RemotePort: &retryPort,
	}, "revision-failure-retry-000001")
	if err != nil {
		t.Fatal(err)
	}
	if retry.Revision != updated.Revision+1 {
		t.Fatalf("failed revision blocked next immutable revision: got=%d want=%d", retry.Revision, updated.Revision+1)
	}

	nextPort := 6303
	next, err := app.UpdateMapping(ctx, client, mapping.ID, MappingRequest{
		Name:       "revision-failure-next",
		ProxyType:  "tcp",
		LocalIP:    "127.0.0.1",
		LocalPort:  8303,
		RemotePort: &nextPort,
	}, "revision-failure-next-000001")
	if err != nil {
		t.Fatal(err)
	}
	var retryStatus string
	if err := app.DB.QueryRowContext(ctx, `SELECT status FROM mapping_revisions WHERE mapping_id=? AND revision=?`, mapping.ID, retry.Revision).Scan(&retryStatus); err != nil {
		t.Fatal(err)
	}
	if retryStatus != "superseded" || next.Revision != retry.Revision+1 {
		t.Fatalf("pending revision was not superseded: status=%q next=%d retry=%d", retryStatus, next.Revision, retry.Revision)
	}
	var retryLease, nextLease int
	if err := app.DB.QueryRowContext(ctx, `SELECT COUNT(1) FROM port_leases WHERE mapping_id=? AND remote_port=?`, mapping.ID, retryPort).Scan(&retryLease); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.QueryRowContext(ctx, `SELECT COUNT(1) FROM port_leases WHERE mapping_id=? AND remote_port=? AND lease_role='pending'`, mapping.ID, nextPort).Scan(&nextLease); err != nil {
		t.Fatal(err)
	}
	if retryLease != 0 || nextLease != 1 {
		t.Fatalf("pending lease replacement failed: old=%d new=%d", retryLease, nextLease)
	}
}
