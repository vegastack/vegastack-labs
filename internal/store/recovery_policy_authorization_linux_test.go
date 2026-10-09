//go:build linux

package store

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"testing"
)

func TestRecoveryPointAuthorizationUsesActualPolicy(t *testing.T) {
	repo, point, _ := seededVerificationPoint(t)
	seedEffectivePrincipal(t, repo.store, "policy-reader", identity.PrincipalHuman, 1)
	seedEffectiveGrant(t, repo.store, "restore-policy", "policy-reader", authorization.RoleAuthor, authorization.ActionAuthor, authorization.Target{Capability: "recovery.restore.author", ResourceKind: "backup-policy", ResourceID: "policy-a"}, "", 1)
	ctx := context.Background()
	request := authorization.Request{Action: authorization.ActionAuthor, Target: authorization.Target{Capability: "recovery.restore.author", ResourceKind: "recovery-point", ResourceID: point.PointID}}
	owners, err := repo.store.WorkflowAuthorizationTargets(ctx, request)
	if err != nil || len(owners) != 1 || owners[0].ResourceID != "policy-a" || owners[0].ResourceKind != "backup-policy" {
		t.Fatal("point owner not grounded in canonical policy", owners, err)
	}
	principal := identity.Principal{ID: "policy-reader", Kind: identity.PrincipalHuman, Method: identity.LocalOSPeerMethod}
	request.Target = owners[0]
	allowed, err := authorization.NewEvaluator(NewEffectiveAuthorizationRepository(repo.store)).Authorize(ctx, principal, request)
	if err != nil || !allowed.Allowed {
		t.Fatal("stable policy grant denied", allowed, err)
	}
	request.Target.ResourceID = "policy-b"
	denied, err := authorization.NewEvaluator(NewEffectiveAuthorizationRepository(repo.store)).Authorize(ctx, principal, request)
	if err != nil || denied.Allowed {
		t.Fatal("unrelated policy borrowed", denied, err)
	}
	request.Target = authorization.Target{Capability: "recovery.restore.author", ResourceKind: "recovery-point", ResourceID: "unknown-point"}
	if _, err = repo.store.WorkflowAuthorizationTargets(ctx, request); err == nil {
		t.Fatal("invented point resolved")
	}
}
