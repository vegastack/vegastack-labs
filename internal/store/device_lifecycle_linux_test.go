//go:build linux

package store

import (
	"context"
	"database/sql"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"testing"
)

func TestDeviceLifecycleDurableAccessAndOwnerDenial(t *testing.T) {
	s := openEffectiveAuthorizationStore(t)
	defer s.Close()
	ctx := context.Background()
	tx, e := s.conn.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = applyUserLifecycle(ctx, tx, lifecycleFixture("onboard"), testAuthorizationTime()); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	in := deviceFixture("request")
	p := identity.Principal{ID: in.PrincipalID, DeviceID: in.DeviceID, Method: identity.LocalOSPeerMethod}
	repo := NewEffectiveAuthorizationRepository(s)
	scopeSeeded := false
	check := func(want bool) {
		t.Helper()
		if got := repo.AuthorizeDevice(ctx, p) == nil; got != want {
			t.Fatalf("access %v want %v", got, want)
		}
		if scopeSeeded {
			attributed := identity.WithVerifiedPrincipal(ctx, p)
			_, err := NewReadAuthorizer(s).AuthorizeRead(attributed, p, authorization.ReadTarget{Capability: "host.read", ResourceKind: "host", ResourceID: "synthetic"})
			if (err == nil) != want {
				t.Fatal("read boundary device status", err, want)
			}
			snap, err := repo.Snapshot(attributed, p.ID, authorization.Target{Capability: "host.read", ResourceKind: "host", ResourceID: "synthetic"})
			if want && (err != nil || len(snap.Grants) != 1) || !want && err == nil {
				t.Fatal("effective boundary device status", snap, err, want)
			}
		}
	}
	apply := func() {
		t.Helper()
		tx, e := s.conn.BeginTx(ctx, nil)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback()
		row := func(q string, a ...any) *sql.Row { return tx.QueryRowContext(ctx, q, a...) }
		if e = validateGrantBatchPrincipal(row, in); e != nil {
			t.Fatal(e)
		}
		if e = applyDeviceLifecycle(ctx, tx, in, testAuthorizationTime()); e != nil {
			t.Fatal(e)
		}
		if e = verifyDeviceLifecycle(row, in); e != nil {
			t.Fatal(e)
		}
		if e = tx.Commit(); e != nil {
			t.Fatal(e)
		}
	}
	check(false)
	apply()
	check(false)
	var n int
	if s.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM effective_authorization_grants WHERE principal_id=?`, p.ID).Scan(&n) != nil || n != 0 {
		t.Fatal("request granted scopes")
	}
	row := func(q string, a ...any) *sql.Row { return s.conn.QueryRowContext(ctx, q, a...) }
	if Code(validateDeviceLifecycle(row, in)) != generated.ErrorCodeStateConflict {
		t.Fatal("duplicate accepted")
	}
	in.DeviceAction = "approve"
	in.ExpectedDeviceRevision = 1
	conflicting := in
	conflicting.PrincipalID = "another-human"
	if validateDeviceLifecycle(row, conflicting) == nil {
		t.Fatal("other human accepted")
	}
	conflicting = in
	conflicting.DeviceID = "another-device"
	if validateDeviceLifecycle(row, conflicting) == nil {
		t.Fatal("other device accepted")
	}
	apply()
	seedEffectiveGrant(t, s, "device-read", in.PrincipalID, authorization.RoleReader, authorization.ActionRead, authorization.Target{Capability: "host.read", ResourceKind: "host", ResourceID: "synthetic"}, "", 1)
	if _, e = s.conn.ExecContext(ctx, `INSERT INTO read_grants VALUES(?,'host.read','host','synthetic',1,'active','now','now')`, in.PrincipalID); e != nil {
		t.Fatal(e)
	}
	scopeSeeded = true
	check(true)
	other := p
	other.ID = "another-human"
	if repo.AuthorizeDevice(ctx, other) == nil {
		t.Fatal("wrong owner access")
	}
	other = p
	other.DeviceID = "another-device"
	if repo.AuthorizeDevice(ctx, other) == nil {
		t.Fatal("wrong device access")
	}
	if validateDeviceLifecycle(row, in) == nil {
		t.Fatal("stale approval accepted")
	}
	for _, status := range []string{"suspended", "active", "revoked"} {
		if _, e = s.conn.ExecContext(ctx, `UPDATE effective_authorization_principals SET status=? WHERE principal_id=?`, status, p.ID); e != nil {
			t.Fatal(e)
		}
		check(status == "active")
	}
	// A revoked owner's device remains denied even while the device is approved.
	// Use another active principal solely to test the device's terminal transition.
	in.DeviceAction = "revoke"
	in.ExpectedDeviceRevision = 2
	tx, e = s.conn.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = applyDeviceLifecycle(ctx, tx, in, testAuthorizationTime()); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	check(false)
	if validateDeviceLifecycle(row, in) == nil {
		t.Fatal("revoked device replay accepted")
	}
	for _, q := range []string{`UPDATE operator_devices SET status='approved'`, `UPDATE operator_devices SET principal_id='someone-else'`, `DELETE FROM operator_devices`} {
		if _, e = s.conn.ExecContext(ctx, q); e == nil {
			t.Fatal("terminal history changed", q)
		}
	}
}
