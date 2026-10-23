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

func TestBrowserIdentityBindingOwnerAndTerminalState(t *testing.T) {
	s := openEffectiveAuthorizationStore(t)
	defer s.Close()
	ctx := context.Background()
	seedEffectivePrincipal(t, s, "human-a", identity.PrincipalHuman, 1)
	if _, e := s.conn.ExecContext(ctx, `INSERT INTO read_principals VALUES('human-a','active',1,'now','now')`); e != nil {
		t.Fatal(e)
	}
	b := bindingFixture()
	digest, e := BrowserIdentityBindingDigest(b)
	if e != nil {
		t.Fatal(e)
	}
	in := lifecycleFixture("")
	in.PrincipalID = "human-a"
	in.IdentityBinding = &b
	row := func(q string, a ...any) *sql.Row { return s.conn.QueryRowContext(ctx, q, a...) }
	if e = validateGrantBatchPrincipal(row, in); e != nil {
		t.Fatal(e)
	}
	if e = validateBrowserIdentityBinding(row, in); e != nil {
		t.Fatal(e)
	}
	tx, e := s.conn.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = applyBrowserIdentityBinding(ctx, tx, in, testAuthorizationTime()); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	if Code(validateBrowserIdentityBinding(row, in)) != generated.ErrorCodeStateConflict {
		t.Fatal("duplicate binding accepted")
	}
	in.PrincipalID = "other-human"
	b.Action = "revoke"
	if Code(validateBrowserIdentityBinding(row, in)) != generated.ErrorCodeStateConflict {
		t.Fatal("other owner revoked binding")
	}
	in.PrincipalID = "human-a"
	if _, e = s.conn.ExecContext(ctx, `UPDATE remote_identity_bindings SET status='revoked' WHERE binding_digest=?`, digest); e != nil {
		t.Fatal(e)
	}
	b.Action = "bind"
	if Code(validateBrowserIdentityBinding(row, in)) != generated.ErrorCodeStateConflict {
		t.Fatal("terminal binding rebound")
	}
	b.Action = "revoke"
	if Code(validateBrowserIdentityBinding(row, in)) != generated.ErrorCodeStateConflict {
		t.Fatal("terminal binding re-revoked")
	}
	var revision, grants int
	if s.conn.QueryRowContext(ctx, `SELECT grant_revision FROM effective_authorization_principals WHERE principal_id='human-a'`).Scan(&revision) != nil || revision != 1 || s.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM effective_authorization_grants WHERE principal_id='human-a'`).Scan(&grants) != nil || grants != 0 {
		t.Fatal("binding changed grants")
	}
	snapshot, e := NewEffectiveAuthorizationRepository(s).Snapshot(ctx, "human-a", authorization.Target{Capability: "host.read", ResourceKind: "host", ResourceID: "synthetic"})
	if e != nil || len(snapshot.Grants) != 0 {
		t.Fatal("binding implicitly granted permissions", snapshot, e)
	}
}
