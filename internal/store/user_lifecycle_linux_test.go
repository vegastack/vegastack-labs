//go:build linux

package store

import (
	"context"
	"database/sql"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"testing"
)

func TestUserLifecyclePreservesGrantsAndDeniesSuspendedPrincipal(t *testing.T) {
	s := openEffectiveAuthorizationStore(t)
	defer s.Close()
	ctx := context.Background()
	in := lifecycleFixture("onboard")
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
		if e = applyUserLifecycle(ctx, tx, in, testAuthorizationTime()); e != nil {
			t.Fatal(e)
		}
		if e = tx.Commit(); e != nil {
			t.Fatal(e)
		}
	}
	apply()
	var n int
	if s.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM effective_authorization_grants WHERE principal_id=?`, in.PrincipalID).Scan(&n) != nil || n != 0 {
		t.Fatal("onboard granted authority")
	}
	target := authorization.Target{Capability: "host.read", ResourceKind: "host", ResourceID: "synthetic-host"}
	seedEffectiveGrant(t, s, "user-read", in.PrincipalID, authorization.RoleReader, authorization.ActionRead, target, "", 1)
	// An independently suspended binding must never become active on user resume.
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if _, e := s.conn.ExecContext(ctx, `INSERT INTO remote_identity_bindings VALUES(?,?,'suspended',?,?)`, digest, in.PrincipalID, testAuthorizationTime(), testAuthorizationTime()); e != nil {
		t.Fatal(e)
	}
	sessionDigest := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if _, e := s.conn.ExecContext(ctx, `INSERT INTO browser_sessions(session_digest,binding_digest,principal_id,status,recovery_epoch,grant_revision,issued_at,last_seen_at,idle_expires_at,absolute_expires_at,external_expires_at) VALUES(?,?,?,'active',0,1,?,?,?,?,?)`, sessionDigest, digest, in.PrincipalID, testAuthorizationTime(), testAuthorizationTime(), testAuthorizationTime(), testAuthorizationTime(), testAuthorizationTime()); e != nil {
		t.Fatal(e)
	}
	in.LifecycleAction = "suspend"
	in.ExpectedGrantRevision = 1
	apply()
	snapshot, e := NewEffectiveAuthorizationRepository(s).Snapshot(ctx, in.PrincipalID, target)
	if e != nil || snapshot.Status == authorization.EffectiveActive || len(snapshot.Grants) != 0 {
		t.Fatalf("suspended authority: %#v %v", snapshot, e)
	}
	in.LifecycleAction = "resume"
	in.ExpectedGrantRevision = 2
	apply()
	snapshot, e = NewEffectiveAuthorizationRepository(s).Snapshot(ctx, in.PrincipalID, target)
	if e != nil || snapshot.Status != authorization.EffectiveActive || len(snapshot.Grants) != 1 || snapshot.GrantRevision != 3 {
		t.Fatalf("resume: %#v %v", snapshot, e)
	}
	var binding string
	if e = s.conn.QueryRowContext(ctx, `SELECT status FROM remote_identity_bindings WHERE binding_digest=?`, digest).Scan(&binding); e != nil || binding != "suspended" {
		t.Fatal("resume reactivated independently suspended binding", binding, e)
	}
	var sessionStatus string
	if e = s.conn.QueryRowContext(ctx, `SELECT status FROM browser_sessions WHERE session_digest=?`, sessionDigest).Scan(&sessionStatus); e != nil || sessionStatus != "revoked" {
		t.Fatal("resume revived revoked session", sessionStatus, e)
	}
	in.LifecycleAction = "suspend"
	in.ExpectedGrantRevision = 3
	apply()
	in.LifecycleAction = "offboard"
	in.ExpectedGrantRevision = 4
	apply()
	in.LifecycleAction = "resume"
	in.ExpectedGrantRevision = 5
	row := func(q string, a ...any) *sql.Row { return s.conn.QueryRowContext(ctx, q, a...) }
	if Code(validateGrantBatchPrincipal(row, in)) != generated.ErrorCodePlanStale {
		t.Fatal("offboarded principal can resume")
	}
	if _, e = s.conn.ExecContext(ctx, `UPDATE read_principals SET status='active' WHERE principal_id=?`, in.PrincipalID); e == nil {
		t.Fatal("terminal read revocation lost")
	}
}

func TestUserLifecycleMigrationPreservesPopulatedAuthority(t *testing.T) {
	db := openCredentialMigrationFixture(t)
	catalog, err := Catalog()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`PRAGMA foreign_keys=ON`); err != nil {
		t.Fatal(err)
	}
	for _, m := range catalog[:35] {
		if _, err = db.Exec(m.SQL); err != nil {
			t.Fatal(m.Name, err)
		}
	}
	for _, q := range []string{
		`INSERT INTO read_principals VALUES('person','active',3,'now','now')`,
		`INSERT INTO effective_authorization_principals VALUES('person','human','active',7,'now','now')`,
		`INSERT INTO read_grants VALUES('person','host.read','host','synthetic',3,'active','now','now')`,
		`INSERT INTO effective_authorization_grants VALUES('g','person','reader','read','host.read','host','synthetic',NULL,7,'active','now','now')`,
	} {
		if _, err = db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.Exec(catalog[35].SQL); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var readRev, effectiveRev int
	if db.QueryRow(`SELECT grant_revision FROM read_principals WHERE principal_id='person'`).Scan(&readRev) != nil || db.QueryRow(`SELECT grant_revision FROM effective_authorization_principals WHERE principal_id='person'`).Scan(&effectiveRev) != nil || readRev != 3 || effectiveRev != 7 {
		t.Fatal("migration lost independent revisions")
	}
	rows, err := db.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatal(err)
	}
	if rows.Next() {
		t.Fatal("foreign key violation")
	}
	rows.Close()
	for _, table := range []string{"read_principals", "effective_authorization_principals"} {
		for _, status := range []string{"suspended", "active", "revoked"} {
			if _, err = db.Exec(`UPDATE `+table+` SET status=? WHERE principal_id='person'`, status); err != nil {
				t.Fatal(err)
			}
		}
		if _, err = db.Exec(`UPDATE ` + table + ` SET status='active' WHERE principal_id='person'`); err == nil {
			t.Fatal("terminal revocation lost", table)
		}
		if _, err = db.Exec(`DELETE FROM ` + table + ` WHERE principal_id='person'`); err == nil {
			t.Fatal("durability lost", table)
		}
	}
}

func TestUserLifecycleProtectsFinalAdministrator(t *testing.T) {
	s := openEffectiveAuthorizationStore(t)
	defer s.Close()
	ctx := context.Background()
	in := lifecycleFixture("onboard")
	tx, err := s.conn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = applyUserLifecycle(ctx, tx, in, testAuthorizationTime()); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	seedEffectiveGrant(t, s, "admin", in.PrincipalID, authorization.RoleControlPlaneAdmin, authorization.ActionAuthor, authorization.Target{Capability: "authorization.policy.write", ResourceKind: "authorization-policy", ResourceID: "someone"}, "", 1)
	in.LifecycleAction = "suspend"
	in.ExpectedGrantRevision = 1
	row := func(q string, a ...any) *sql.Row { return s.conn.QueryRowContext(ctx, q, a...) }
	if Code(validateGrantBatchPrincipal(row, in)) != generated.ErrorCodeAuthorizationDenied {
		t.Fatal("final administrator suspension allowed")
	}
	in.LifecycleAction = "offboard"
	if Code(validateGrantBatchPrincipal(row, in)) != generated.ErrorCodeAuthorizationDenied {
		t.Fatal("final administrator offboarding allowed")
	}
}
