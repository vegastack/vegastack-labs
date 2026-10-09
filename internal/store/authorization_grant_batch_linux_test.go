//go:build linux

package store

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"testing"
	"time"
)

func TestGrantBatchStageIsInert(t *testing.T) {
	s := openEffectiveAuthorizationStore(t)
	defer s.Close()
	seedEffectivePrincipal(t, s, "operator", identity.PrincipalHuman, 1)
	if _, err := s.conn.ExecContext(context.Background(), `INSERT INTO read_principals VALUES('operator','active',1,'now','now')`); err != nil {
		t.Fatal(err)
	}
	seedEffectiveGrant(t, s, "policy-author", "operator", authorization.RoleControlPlaneAdmin, authorization.ActionAuthor, authorization.Target{Capability: "authorization.policy.write", ResourceKind: "authorization-policy", ResourceID: "operator"}, "", 1)
	ctx := identity.WithVerifiedPrincipal(context.Background(), identity.Principal{ID: "operator", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman})
	rev, err := NewPlanRepository(s).CurrentRevision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	in := generated.AuthorizationGrantBatchRequest{Schema: "vegastack-labs.dev/authorization-grant-batch-request", SchemaVersion: "1.0.0", PrincipalID: "operator", ExpectedGrantRevision: 1, ExpectedStateRevision: rev.StateRevision, RecoveryEpoch: rev.RecoveryEpoch, IdempotencyKey: "batch", ReasonDigest: testDigest, Changes: []generated.AuthorizationGrantChange{{Schema: "vegastack-labs.dev/authorization-grant-change", SchemaVersion: "1.0.0", GrantID: "host-read", Change: "add", RoleID: "reader", Action: "read", Capability: "host.read", ResourceKind: "host", ResourceID: "subject", Branch: ""}}}
	request, err := NewGrantBatchRepository(s).Stage(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	doc := generated.DeclarationRevision{Schema: generated.SchemaIDDeclarationRevision, SchemaVersion: "1.0.0", AuthorizationGrantBatch: request.AuthorizationGrantBatch, DeclarationID: request.DeclarationID, DeclarationType: request.DeclarationType, Revision: request.ExpectedRevision, StateRevision: rev.StateRevision + 1, RecoveryEpoch: rev.RecoveryEpoch, Operations: request.Operations, Extensions: request.Extensions, Status: "draft", CreatedAt: time.Now().UTC().Truncate(time.Second).Format(time.RFC3339), CreatedBy: "operator", AgentSessionID: "software-test"}
	doc.ContentDigest = declarationContentDigest(doc, in.ReasonDigest)
	stored, err := NewDeclarationRepository(s).CreateRevision(ctx, DeclarationRevisionRequest{Document: doc, ReasonDigest: in.ReasonDigest, Expected: rev, KeyDigest: hostaction.Digest("stage-test"), RequestDigest: hostaction.Digest(request), Attribution: audit.Attribution{AuthenticatedPrincipalID: "operator", AuthenticatedPrincipalMethod: identity.LocalOSPeerMethod}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewDeclarationRepository(s).GetRevision(ctx, stored.Document.DeclarationID, stored.Document.Revision); err != nil {
		t.Fatal(err)
	}
	var desired, effective int
	if s.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM desired_authorization_grants`).Scan(&desired) != nil || s.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM effective_authorization_grants`).Scan(&effective) != nil || desired != 1 || effective != 1 {
		t.Fatal("staging changed effective authority", desired, effective)
	}
	if _, err = NewGrantBatchRepository(s).Stage(ctx, in); Code(err) != generated.ErrorCodePlanStale {
		t.Fatal("old batch accepted after state changed", err)
	}
	principal := identity.Principal{ID: "operator", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}
	navigation := authorization.Request{DeclarationRevision: stored.Document.Revision, Action: authorization.ActionAuthor, Target: authorization.Target{Capability: "plan.author", ResourceKind: "declaration", ResourceID: stored.Document.DeclarationID}}
	exact, err := authorization.NewEvaluator(NewEffectiveAuthorizationRepository(s)).Authorize(ctx, principal, navigation)
	if err != nil || exact.Allowed {
		t.Fatal("regression precondition: exact future-ID grant unexpectedly exists", err)
	}
	owners, err := s.WorkflowAuthorizationTargets(ctx, navigation)
	if err != nil || len(owners) != 1 {
		t.Fatal("sealed workflow owner unresolved", owners, err)
	}
	mappedRequest := navigation
	mappedRequest.Target = owners[0]
	mapped, err := authorization.NewEvaluator(NewEffectiveAuthorizationRepository(s)).Authorize(ctx, principal, mappedRequest)
	if err != nil || !mapped.Allowed || mapped.Scope.ResourceID != "operator" || mapped.Scope.Capability != "authorization.policy.write" {
		t.Fatal("sealed policy workflow denied without guessed future-ID grant", mapped, err)
	}
	bad := navigation
	bad.Target.ResourceID = GrantBatchDeclarationID("other-principal")
	if _, err = s.WorkflowAuthorizationTargets(ctx, bad); err == nil {
		t.Fatal("unrelated subject resolved")
	}
	if _, err = s.conn.ExecContext(ctx, `UPDATE effective_authorization_grants SET status='revoked' WHERE grant_id='policy-author'`); err != nil {
		t.Fatal(err)
	}
	if denied, e := authorization.NewEvaluator(NewEffectiveAuthorizationRepository(s)).Authorize(ctx, principal, mappedRequest); e != nil || denied.Allowed {
		t.Fatal("revoked policy owner still authorizes its workflow", denied, e)
	}

}
