package api

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"net/http/httptest"
	"testing"
)

type workflowOwnerFixture struct {
	owners []authorization.Target
	calls  int
}

func (f *workflowOwnerFixture) WorkflowAuthorizationTargets(context.Context, authorization.Request) ([]authorization.Target, error) {
	f.calls++
	return f.owners, nil
}

func TestWorkflowNavigationKeepsExactResourceDecisions(t *testing.T) {
	owner := authorization.Target{Capability: "authorization.policy.write", ResourceKind: "authorization-policy", ResourceID: "operator-a"}
	for _, variant := range []string{"allowed", "other-owner", "recursive-owner", "stale", "mixed-read", "missing-read"} {
		t.Run(variant, func(t *testing.T) {
			recorder := &authorizationRecorderStub{}
			app := newAuthorizationTestApplication(t, authorization.NewEvaluator(apiPolicyRepository{snapshot: authorization.EffectivePolicySnapshot{PrincipalKind: identity.PrincipalHuman, Status: authorization.EffectiveActive, GrantRevision: 7, StateRevision: 12, RecoveryEpoch: 3, Grants: []authorization.EffectiveGrant{{Role: authorization.RoleControlPlaneAdmin, AllowedAction: authorization.ActionAuthor, Capability: owner.Capability, ResourceKind: owner.ResourceKind, ResourceID: owner.ResourceID}}}}), recorder)
			resolver := &workflowOwnerFixture{owners: []authorization.Target{owner}}
			if variant == "mixed-read" || variant == "missing-read" {
				resolver.owners = append(resolver.owners, authorization.Target{Capability: "host.read", ResourceKind: "host", ResourceID: "host-a"})
				if variant == "mixed-read" {
					app.effective.Authorizer = authorization.NewEvaluator(apiPolicyRepository{snapshot: authorization.EffectivePolicySnapshot{PrincipalKind: identity.PrincipalHuman, Status: authorization.EffectiveActive, GrantRevision: 7, StateRevision: 12, RecoveryEpoch: 3, Grants: []authorization.EffectiveGrant{
						{Role: authorization.RoleControlPlaneAdmin, AllowedAction: authorization.ActionAuthor, Capability: owner.Capability, ResourceKind: owner.ResourceKind, ResourceID: owner.ResourceID},
						{Role: authorization.RoleReader, AllowedAction: authorization.ActionRead, Capability: "host.read", ResourceKind: "host", ResourceID: "host-a"},
					}}})
				}
			}
			if variant == "other-owner" {
				other := owner
				other.ResourceID = "operator-b"
				resolver.owners = append(resolver.owners, other)
			}
			if variant == "recursive-owner" {
				resolver.owners[0] = authorization.Target{Capability: "plan.author", ResourceKind: "declaration", ResourceID: "recursive"}
			}
			app.effective.WorkflowOwners = resolver
			request := httptest.NewRequest("POST", "/api/v1/declarations/generated-policy/plans", nil)
			principal := identity.Principal{ID: "human-maintainer", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}
			input := authorization.Request{Action: authorization.ActionAuthor, Target: authorization.Target{Capability: "plan.author", ResourceKind: "declaration", ResourceID: "generated-policy"}}
			if variant == "stale" {
				input.Expected = &authorization.RevisionBinding{GrantRevision: 7, StateRevision: 11, RecoveryEpoch: 3}
			}
			out, err := app.authorizePrincipal(request.Context(), principal, input)
			if variant == "allowed" || variant == "mixed-read" {
				expectedRecords := 1
				if variant == "mixed-read" {
					expectedRecords = 2
				}
				if err != nil || out.Scope.ResourceID != owner.ResourceID || len(recorder.records) != expectedRecords || recorder.records[0].Decision.Target != owner {
					t.Fatal("resource authority not recorded exactly once", out, err, recorder.records)
				}
			} else if err == nil {
				t.Fatal("unsafe navigation accepted")
			}
			if resolver.calls != 1 {
				t.Fatal("owner resolver recursion", resolver.calls)
			}
			for _, record := range recorder.records {
				if !authorization.ValidDecisionRecord(record) {
					t.Fatal("invalid resource audit", record)
				}
			}
		})
	}
}

func TestWorkflowOwnerCannotReplaceExecutionAuthorization(t *testing.T) {
	recorder := &authorizationRecorderStub{}
	app := newAuthorizationTestApplication(t, authorization.NewEvaluator(apiPolicyRepository{snapshot: authorization.EffectivePolicySnapshot{PrincipalKind: identity.PrincipalHuman, Status: authorization.EffectiveActive, GrantRevision: 7, StateRevision: 12, RecoveryEpoch: 3}}), recorder)
	resolver := &workflowOwnerFixture{owners: []authorization.Target{{Capability: "authorization.policy.write", ResourceKind: "authorization-policy", ResourceID: "operator-a"}}}
	app.effective.WorkflowOwners = resolver
	request := httptest.NewRequest("POST", "/api/v1/plans/plan-test/execute", nil)
	request = request.WithContext(identity.WithVerifiedPrincipal(request.Context(), identity.Principal{ID: "human-maintainer", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}))
	_, err := app.authorizePlanAction(request, authorization.ActionExecute, authorization.Target{Capability: "application.deploy", ResourceKind: "application", ResourceID: "app-test"}, apiAuthorizationPlan(authorization.BranchHuman), []authorization.Branch{authorization.BranchHuman}, authorization.RevisionBinding{GrantRevision: 7, StateRevision: 12, RecoveryEpoch: 3})
	if err == nil || resolver.calls != 0 {
		t.Fatal("owner navigation substituted execution authority", err, resolver.calls)
	}
}
