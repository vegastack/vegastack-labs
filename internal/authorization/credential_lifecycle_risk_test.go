package authorization

import (
	"context"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

func TestCredentialLifecycleRiskIsClosedControlPlane(t *testing.T) {
	for _, action := range []string{"credential.stage", "credential.activate", "credential.rotate", "credential.revoke", "credential.recover"} {
		t.Run(action, func(t *testing.T) {
			plan := generated.Plan{Risk: string(RiskControlPlane), Operations: []generated.PlanOperation{{Sequence: 1, OperationType: action}}}
			if risk, err := ClassifyPlan(plan); err != nil || risk != RiskControlPlane {
				t.Fatalf("exact lifecycle risk = %q, %v", risk, err)
			}
			for _, wrong := range []RiskClass{RiskRoutine, RiskDestructive} {
				plan.Risk = string(wrong)
				if _, err := ClassifyPlan(plan); err == nil {
					t.Fatalf("accepted stale embedded risk %q", wrong)
				}
			}
		})
	}
	unknown := generated.Plan{Risk: string(RiskControlPlane), Operations: []generated.PlanOperation{{Sequence: 1, OperationType: "credential.unknown"}}}
	if _, err := ClassifyPlan(unknown); err == nil {
		t.Fatal("accepted unknown credential operation")
	}
}

func TestCredentialLifecycleCannotUsePolicyPreauthorization(t *testing.T) {
	for _, action := range []string{"credential.stage", "credential.activate", "credential.rotate", "credential.revoke", "credential.recover"} {
		plan := testPlan(action, BranchPreauthorized)
		plan.Risk = string(RiskControlPlane)
		policy := identity.Principal{ID: "policy-lifecycle", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalPolicy}
		evaluator := NewEvaluator(policyRepositoryStub{snapshot: EffectivePolicySnapshot{PrincipalKind: policy.Kind, Status: EffectiveActive, GrantRevision: 1, StateRevision: plan.Binding.StateRevision, RecoveryEpoch: plan.Binding.RecoveryEpoch, Grants: []EffectiveGrant{{Role: RolePreauthorizedExecutor, AllowedAction: ActionExecute, Capability: action, ResourceKind: "execution-target", ResourceID: "app-test", Branch: BranchPreauthorized}}}})
		decision, err := evaluator.Authorize(context.Background(), policy, Request{Action: ActionExecute, Target: Target{Capability: action, ResourceKind: "execution-target", ResourceID: "app-test"}, Plan: &plan, Branches: []Branch{BranchPreauthorized}})
		if err != nil || decision.Allowed || decision.ReasonCode != ReasonPreauthorizationDenied {
			t.Fatalf("%s policy preauthorization = %+v %v", action, decision, err)
		}
	}
}
