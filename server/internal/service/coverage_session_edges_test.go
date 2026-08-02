package service

import (
	"context"
	"testing"
)

func TestSessionAndPortLeaseDatabaseFailureEdges(t *testing.T) {
	fixture := newServiceCoverageFixture(t)
	ctx := context.Background()
	app := fixture.app
	if _, err := app.Authenticate(ctx, fixture.adminLogin.Token); err != nil {
		t.Fatal(err)
	}
	if err := fixture.database.Close(); err != nil {
		t.Fatal(err)
	}
	if err := app.Logout(ctx, fixture.admin, "closed-db"); err == nil {
		t.Fatal("logout hid a database failure")
	}
	if _, _, err := app.IssueReauthTicket(ctx, fixture.admin, app.Config.AdminPassword); err == nil {
		t.Fatal("reauth ticket issuance hid a database failure")
	}
	if err := app.RequireReauthTicket(ctx, fixture.admin, "ticket"); err == nil {
		t.Fatal("reauth ticket verification hid a database failure")
	}
	if err := app.TouchSession(ctx, fixture.admin); err == nil {
		t.Fatal("session touch hid a database failure")
	}

	fixture2 := newServiceCoverageFixture(t)
	tx, err := fixture2.database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := allocatePort(ctx, tx, 6000, 6000); err == nil {
		t.Fatal("port allocator hid a completed transaction failure")
	}
	if err := fixture2.database.Close(); err != nil {
		t.Fatal(err)
	}
}
