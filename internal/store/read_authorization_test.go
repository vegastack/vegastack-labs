package store

import (
	"context"
	"runtime"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

func TestReadAuthorizationDefaultsEmptyAndNeverInfersAdmin(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("SQLite authority is supported on Linux")
	}
	s, err := Open(context.Background(), testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	authorizer := NewReadAuthorizer(s)
	for _, principal := range []identity.Principal{{ID: "principal-root", Method: identity.LocalOSPeerMethod}, {ID: "principal-service-owner", Method: identity.LocalOSPeerMethod}} {
		_, err := authorizer.AuthorizeRead(context.Background(), principal, authorization.ReadTarget{Capability: "platform.summary.read", ResourceKind: "platform-summary", ResourceID: "current"})
		if Code(err) != generated.ErrorCodeAuthorizationDenied {
			t.Fatalf("principal %q error = %v", principal.ID, err)
		}
	}
	for _, table := range []string{"read_principals", "read_grants"} {
		var count int
		if err := s.conn.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM "+table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("%s contains %d inferred rows", table, count)
		}
	}
}

func TestReadAuthorizationReturnsCanonicalScopedDigest(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("SQLite authority is supported on Linux")
	}
	s, err := Open(context.Background(), testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	seedReadGrant(t, s, "principal-reader", "inventory.draft.read", "inventory-draft", "draft-b:1", 4, "active")
	seedReadGrant(t, s, "principal-reader", "inventory.draft.read", "inventory-draft", "draft-a:1", 4, "active")
	authorizer := NewReadAuthorizer(s)
	scope, err := authorizer.AuthorizeRead(context.Background(), identity.Principal{ID: "principal-reader", Method: identity.LocalOSPeerMethod}, authorization.ReadTarget{Capability: "inventory.draft.read", ResourceKind: "inventory-draft"})
	if err != nil {
		t.Fatal(err)
	}
	if scope.PrincipalID != "principal-reader" || scope.GrantRevision != 4 || scope.ScopeDigest == "" {
		t.Fatalf("scope = %#v", scope)
	}
	if scope.ScopeDigest != scopeDigest("principal-reader", "inventory.draft.read", "inventory-draft", 4, []string{"draft-a:1", "draft-b:1"}) {
		t.Fatalf("scope digest = %q", scope.ScopeDigest)
	}
	if _, err := authorizer.AuthorizeRead(context.Background(), identity.Principal{ID: "principal-reader", Method: identity.LocalOSPeerMethod}, authorization.ReadTarget{Capability: "inventory.draft.read", ResourceKind: "inventory-draft", ResourceID: "draft-c:1"}); Code(err) != generated.ErrorCodeAuthorizationDenied {
		t.Fatalf("cross-resource error = %v", err)
	}
}

func seedReadGrant(t *testing.T, s *Store, principal, capability, kind, resource string, revision int64, status string) {
	t.Helper()
	now := "2026-09-09T12:00:00Z"
	if _, err := s.conn.ExecContext(context.Background(), `INSERT OR IGNORE INTO read_principals(principal_id,status,grant_revision,created_at,updated_at) VALUES(?,?,?,?,?)`, principal, "active", revision, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.conn.ExecContext(context.Background(), `INSERT INTO read_grants(principal_id,capability,resource_kind,resource_id,grant_revision,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)`, principal, capability, kind, resource, revision, status, now, now); err != nil {
		t.Fatal(err)
	}
}
