//go:build linux

package store

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"strings"
	"testing"
)

func operatorReadFixture(t *testing.T) (*Store, context.Context, *OperatorAccessRepository) {
	t.Helper()
	s := openEffectiveAuthorizationStore(t)
	t.Cleanup(func() { s.Close() })
	for _, id := range []string{"operator", "person-a", "person-b", "private-person"} {
		seedEffectivePrincipal(t, s, id, identity.PrincipalHuman, 1)
		if _, e := s.conn.ExecContext(context.Background(), `INSERT INTO read_principals VALUES(?,'active',1,'now','now')`, id); e != nil {
			t.Fatal(e)
		}
	}
	for _, id := range []string{"person-a", "person-b"} {
		seedEffectiveGrant(t, s, "read-"+id, "operator", authorization.RoleInfrastructureAdmin, authorization.ActionRead, authorization.Target{Capability: "authorization.policy.read", ResourceKind: "authorization-policy", ResourceID: id}, "", 1)
	}
	for _, id := range []string{"device-a", "device-b"} {
		if _, e := s.conn.ExecContext(context.Background(), `INSERT INTO operator_devices VALUES(?,'person-a','approved',1,'now','now')`, id); e != nil {
			t.Fatal(e)
		}
	}
	seedEffectiveGrant(t, s, "person-a-grant", "person-a", authorization.RoleInfrastructureAdmin, authorization.ActionRead, authorization.Target{Capability: "host.read", ResourceKind: "host", ResourceID: "host-a"}, "", 1)
	ctx := identity.WithVerifiedPrincipal(context.Background(), identity.Principal{ID: "operator", Kind: identity.PrincipalHuman, Method: identity.LocalOSPeerMethod})
	return s, ctx, NewOperatorAccessRepository(s)
}
func TestOperatorAccessScopedPagingAndSafeProjection(t *testing.T) {
	s, ctx, r := operatorReadFixture(t)
	var before int
	if err := s.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_events`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	page, e := r.ListPeople(ctx, "", 1)
	if e != nil || len(page.People) != 1 || page.People[0].PrincipalID != "person-a" || page.NextAfter != "person-a" {
		t.Fatalf("first page: %#v %v", page, e)
	}
	next, e := r.ListPeople(ctx, page.NextAfter, 1)
	if e != nil || len(next.People) != 1 || next.People[0].PrincipalID != "person-b" || next.NextAfter != "" {
		t.Fatalf("next page: %#v %v", next, e)
	}
	d, e := r.ListDevices(ctx, "person-a", "", 1)
	if e != nil || len(d.Devices) != 1 || d.Devices[0].DeviceID != "device-a" || d.NextAfter != "device-a" {
		t.Fatalf("devices: %#v %v", d, e)
	}
	g, e := r.ListGrants(ctx, "person-a", "", 100)
	if e != nil || len(g.Grants) != 1 || g.Grants[0].ResourceID != "host-a" {
		t.Fatalf("grants: %#v %v", g, e)
	}
	for _, v := range []struct {
		id string
		v  any
	}{{generated.SchemaIDOperatorPeoplePage, page}, {generated.SchemaIDOperatorDeviceList, d}, {generated.SchemaIDOperatorGrantList, g}} {
		raw, _ := json.Marshal(v.v)
		if e := generated.ValidateContractJSON(v.id, raw, generated.ContractExact); e != nil {
			t.Fatal(e)
		}
		for _, secret := range []string{"binding", "subject", "token", "session", "private-person", "created_at"} {
			if strings.Contains(string(raw), secret) {
				t.Fatalf("unsafe field: %s", raw)
			}
		}
	}
	if _, e = r.ListDevices(ctx, "private-person", "", 100); e == nil {
		t.Fatal("wrong-owner devices disclosed")
	}
	if _, e = r.ListGrants(ctx, "private-person", "", 100); e == nil {
		t.Fatal("wrong-owner grants disclosed")
	}
	if _, e = r.ListPeople(ctx, "", 101); e == nil {
		t.Fatal("unbounded query accepted")
	}
	var after int
	if err := s.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_events`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatal("read changed audit state")
	}
}
func TestOperatorAccessFreshActorDeviceAndGrantDenials(t *testing.T) {
	for _, mode := range []string{"missing", "suspended", "revoked", "read-suspended", "stale-grant", "revoked-grant", "device-revoked", "device-wrong-owner"} {
		t.Run(mode, func(t *testing.T) {
			s, ctx, r := operatorReadFixture(t)
			exec := func(q string, args ...any) {
				t.Helper()
				if _, err := s.conn.ExecContext(ctx, q, args...); err != nil {
					t.Fatal(err)
				}
			}
			switch mode {
			case "missing":
				ctx = context.Background()
			case "suspended", "revoked":
				exec(`UPDATE effective_authorization_principals SET status=? WHERE principal_id='operator'`, mode)
			case "read-suspended":
				exec(`UPDATE read_principals SET status='suspended' WHERE principal_id='operator'`)
			case "stale-grant":
				exec(`UPDATE effective_authorization_principals SET grant_revision=2 WHERE principal_id='operator'`)
			case "revoked-grant":
				exec(`UPDATE effective_authorization_grants SET status='revoked' WHERE principal_id='operator'`)
			case "device-revoked", "device-wrong-owner":
				owner := "operator"
				status := "revoked"
				if mode == "device-wrong-owner" {
					owner = "person-a"
					status = "approved"
				}
				exec(`INSERT INTO operator_devices VALUES('caller-device',?,?,1,'now','now')`, owner, status)
				ctx = identity.WithVerifiedPrincipal(ctx, identity.Principal{ID: "operator", DeviceID: "caller-device", Kind: identity.PrincipalHuman, Method: identity.LocalOSPeerMethod})
			}
			if _, e := r.ListPeople(ctx, "", 100); e == nil {
				t.Fatal("people disclosed")
			}
			if _, e := r.ListDevices(ctx, "person-a", "", 100); e == nil {
				t.Fatal("devices disclosed")
			}
			if _, e := r.ListGrants(ctx, "person-a", "", 100); e == nil {
				t.Fatal("grants disclosed")
			}
		})
	}
}

func TestOperatorAccessProviderScopeIsExactAndFresh(t *testing.T) {
	s, ctx, r := operatorReadFixture(t)
	seedReadGrant(t, s, "operator", "platform.source.read", "platform-source", "providers", 1, "active")
	principal, _ := identity.PrincipalFromContext(ctx)
	scope, err := NewReadAuthorizer(s).AuthorizeRead(ctx, principal, authorization.ReadTarget{Capability: "platform.source.read", ResourceKind: "platform-source", ResourceID: "providers"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.ProviderRevision(ctx, scope); err != nil {
		t.Fatal(err)
	}
	forged := scope
	forged.ScopeDigest = "sha256:" + strings.Repeat("a", 64)
	if _, err = r.ProviderRevision(ctx, forged); err == nil {
		t.Fatal("forged provider scope accepted")
	}
	if _, err = s.conn.ExecContext(ctx, `UPDATE read_grants SET status='revoked' WHERE principal_id='operator' AND resource_id='providers'`); err != nil {
		t.Fatal(err)
	}
	if _, err = r.ProviderRevision(ctx, scope); err == nil {
		t.Fatal("revoked provider read accepted")
	}
}
