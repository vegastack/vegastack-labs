package authorization

import (
	"context"
	"errors"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

type policyRepositoryStub struct {
	snapshot EffectivePolicySnapshot
	err      error
}

func (repository policyRepositoryStub) Snapshot(_ context.Context, principalID string, _ Target) (EffectivePolicySnapshot, error) {
	repository.snapshot.PrincipalID = principalID
	return repository.snapshot, repository.err
}

func TestAutomaticBranchNeverCoversProductionRestoreDeleteOrRetention(t *testing.T) {
	t.Parallel()
	operations := []string{"application.deploy.production-like", "backup.restore", "resource.delete", "backup.retention.change"}
	for _, operation := range operations {
		operation := operation
		t.Run(operation, func(t *testing.T) {
			t.Parallel()
			plan := testPlan(operation, BranchPreauthorized)
			decision, _ := evaluatorFor(RolePreauthorizedExecutor, identity.PrincipalPolicy).Authorize(context.Background(), identity.Principal{ID: "policy-deployer", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalPolicy}, Request{
				Action:   ActionExecute,
				Target:   Target{Capability: "application.deploy", ResourceKind: "application", ResourceID: "app-test"},
				Plan:     &plan,
				Branches: []Branch{BranchPreauthorized},
			})
			if decision.Allowed || decision.Branch != nil {
				t.Fatalf("%s widened automatic authority: %#v", operation, decision)
			}
		})
	}
}

func TestPolicyMatrixDeniesAgentsAcknowledgingAndRequiresExactBranch(t *testing.T) {
	t.Parallel()
	plan := testPlan("application.deploy.low-risk", BranchHuman)
	agentEvaluator := evaluatorFor(RoleMaintainer, identity.PrincipalAgent)
	decision, err := agentEvaluator.Authorize(context.Background(), identity.Principal{ID: "agent-codex", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalAgent}, Request{
		Action:   ActionAcknowledge,
		Target:   Target{Capability: "application.deploy", ResourceKind: "application", ResourceID: "app-test"},
		Plan:     &plan,
		Branches: []Branch{BranchHuman},
	})
	if err != nil || decision.Allowed || decision.ReasonCode != ReasonAgentCannotAcknowledge {
		t.Fatalf("agent acknowledgement = %#v, %v", decision, err)
	}

	policyPlan := testPlan("application.deploy.low-risk", BranchPreauthorized)
	decision, err = evaluatorFor(RolePreauthorizedExecutor, identity.PrincipalPolicy).Authorize(context.Background(), identity.Principal{ID: "policy-deployer", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalPolicy}, Request{
		Action:   ActionExecute,
		Target:   Target{Capability: "application.deploy", ResourceKind: "application", ResourceID: "app-test"},
		Plan:     &policyPlan,
		Branches: []Branch{BranchHuman, BranchPreauthorized},
	})
	if err != nil || decision.Allowed || decision.ReasonCode != ReasonAuthorizationBranch {
		t.Fatalf("mixed branch = %#v, %v", decision, err)
	}
}

func TestEvaluatorDeniesStaleBindingsUnknownPolicyAndRepositoryFailure(t *testing.T) {
	t.Parallel()
	principal := identity.Principal{ID: "human-maintainer", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}
	plan := testPlan("application.deploy.production-like", BranchHuman)
	evaluator := evaluatorFor(RoleMaintainer, identity.PrincipalHuman)
	request := Request{Action: ActionExecute, Target: Target{Capability: "application.deploy", ResourceKind: "application", ResourceID: "app-test"}, Plan: &plan, Branches: []Branch{BranchHuman}, Expected: &RevisionBinding{GrantRevision: 8, StateRevision: 12, RecoveryEpoch: 3}}
	if decision, _ := evaluator.Authorize(context.Background(), principal, request); decision.Allowed || decision.ReasonCode != ReasonGrantRevisionStale {
		t.Fatalf("stale grant = %#v", decision)
	}

	request.Expected.GrantRevision = 7
	request.Expected.RecoveryEpoch = 4
	if decision, _ := evaluator.Authorize(context.Background(), principal, request); decision.Allowed || decision.ReasonCode != ReasonRecoveryEpochMismatch {
		t.Fatalf("recovery mismatch = %#v", decision)
	}

	unknownPlan := testPlan("provider.magic", BranchHuman)
	request.Expected.RecoveryEpoch = 3
	request.Plan = &unknownPlan
	if decision, _ := evaluator.Authorize(context.Background(), principal, request); decision.Allowed || decision.ReasonCode != ReasonRiskUnknown {
		t.Fatalf("unknown risk = %#v", decision)
	}

	request.Plan = &plan
	request.Expected.RecoveryEpoch = 0
	if decision, _ := evaluator.Authorize(context.Background(), principal, request); decision.Allowed || decision.ReasonCode != ReasonRecoveryEpochMismatch {
		t.Fatalf("initial-epoch replay = %#v", decision)
	}

	repositoryFailure := errors.New("database unavailable")
	failed := NewEvaluator(policyRepositoryStub{err: repositoryFailure})
	decision, err := failed.Authorize(context.Background(), principal, request)
	if !errors.Is(err, repositoryFailure) || decision.Allowed || decision.ReasonCode != ReasonPolicyUnavailable {
		t.Fatalf("repository failure = %#v, %v", decision, err)
	}
}

func TestRoleActionRiskMatrixIsClosed(t *testing.T) {
	t.Parallel()
	roles := []Role{RoleReader, RoleAuthor, RoleMaintainer, RoleInfrastructureAdmin, RoleControlPlaneAdmin, RolePreauthorizedExecutor, Role("unknown")}
	actions := []Action{ActionRead, ActionAuthor, ActionAcknowledge, ActionExecute, Action("unknown")}
	risks := []RiskClass{RiskRoutine, RiskProductionLike, RiskInfrastructure, RiskDestructive, RiskControlPlane, RiskClass("unknown")}
	for _, role := range roles {
		for _, action := range actions {
			for _, risk := range risks {
				if roleAllows(role, action, risk) && (!ValidRole(role) || !ValidAction(action) || !ValidRiskClass(risk)) {
					t.Fatalf("open matrix accepted role=%q action=%q risk=%q", role, action, risk)
				}
			}
		}
	}
}

func TestAllowedPolicyPathsRemainNarrowAndResourceScoped(t *testing.T) {
	t.Parallel()
	policy := identity.Principal{ID: "policy-deployer", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalPolicy}
	plan := testPlan("application.deploy.low-risk", BranchPreauthorized)
	evaluator := NewEvaluator(policyRepositoryStub{snapshot: EffectivePolicySnapshot{
		PrincipalKind: identity.PrincipalPolicy, Status: EffectiveActive, GrantRevision: 4, StateRevision: 12, RecoveryEpoch: 3,
		Grants: []EffectiveGrant{{Role: RolePreauthorizedExecutor, AllowedAction: ActionExecute, Capability: "application.deploy", ResourceKind: "application", ResourceID: "app-test", Branch: BranchPreauthorized}},
	}})
	request := Request{Action: ActionExecute, Target: Target{Capability: "application.deploy", ResourceKind: "application", ResourceID: "app-test"}, Plan: &plan, Branches: []Branch{BranchPreauthorized}}
	decision, err := evaluator.Authorize(context.Background(), policy, request)
	if err != nil || !decision.Allowed || decision.Branch == nil || *decision.Branch != BranchPreauthorized || decision.Scope.ScopeDigest == "" {
		t.Fatalf("eligible policy decision = %#v, %v", decision, err)
	}

	request.Target.ResourceID = "app-other"
	decision, err = evaluator.Authorize(context.Background(), policy, request)
	if err != nil || decision.Allowed || decision.ReasonCode != ReasonPreauthorizationDenied {
		t.Fatalf("widened target decision = %#v, %v", decision, err)
	}
}

func TestRoleActionRiskMatrixMatchesPolicy(t *testing.T) {
	t.Parallel()
	tests := []struct {
		role   Role
		action Action
		risk   RiskClass
		allow  bool
	}{
		{RoleReader, ActionRead, RiskRoutine, true},
		{RoleReader, ActionAuthor, RiskRoutine, false},
		{RoleAuthor, ActionAuthor, RiskRoutine, true},
		{RoleAuthor, ActionAcknowledge, RiskRoutine, false},
		{RoleMaintainer, ActionExecute, RiskProductionLike, true},
		{RoleMaintainer, ActionExecute, RiskInfrastructure, false},
		{RoleInfrastructureAdmin, ActionExecute, RiskDestructive, true},
		{RoleInfrastructureAdmin, ActionExecute, RiskControlPlane, false},
		{RoleControlPlaneAdmin, ActionExecute, RiskControlPlane, true},
		{RolePreauthorizedExecutor, ActionExecute, RiskRoutine, true},
		{RolePreauthorizedExecutor, ActionExecute, RiskProductionLike, false},
	}
	for _, test := range tests {
		if got := roleAllows(test.role, test.action, test.risk); got != test.allow {
			t.Errorf("roleAllows(%q, %q, %q) = %t, want %t", test.role, test.action, test.risk, got, test.allow)
		}
	}
}

func TestMalformedEffectiveGrantCannotWidenAuthority(t *testing.T) {
	t.Parallel()
	principal := identity.Principal{ID: "policy-deployer", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalPolicy}
	plan := testPlan("application.deploy.low-risk", BranchPreauthorized)
	target := Target{Capability: "application.deploy", ResourceKind: "application", ResourceID: "app-test"}
	grants := []EffectiveGrant{
		{Role: RolePreauthorizedExecutor, AllowedAction: ActionExecute, Capability: target.Capability, ResourceKind: target.ResourceKind, ResourceID: "", Branch: BranchPreauthorized},
		{Role: RoleMaintainer, AllowedAction: ActionExecute, Capability: target.Capability, ResourceKind: target.ResourceKind, ResourceID: target.ResourceID, Branch: BranchPreauthorized},
		{Role: RolePreauthorizedExecutor, AllowedAction: ActionExecute, Capability: target.Capability, ResourceKind: target.ResourceKind, ResourceID: target.ResourceID, Branch: BranchHuman},
	}
	for index, grant := range grants {
		evaluator := NewEvaluator(policyRepositoryStub{snapshot: EffectivePolicySnapshot{PrincipalKind: identity.PrincipalPolicy, Status: EffectiveActive, GrantRevision: 1, StateRevision: 12, RecoveryEpoch: 3, Grants: []EffectiveGrant{grant}}})
		decision, err := evaluator.Authorize(context.Background(), principal, Request{Action: ActionExecute, Target: target, Plan: &plan, Branches: []Branch{BranchPreauthorized}})
		if err != nil || decision.Allowed || decision.Scope.ScopeDigest != "" {
			t.Fatalf("malformed grant %d widened authority: %#v, %v", index, decision, err)
		}
	}
}

func evaluatorFor(role Role, kind identity.PrincipalKind) *Evaluator {
	return NewEvaluator(policyRepositoryStub{snapshot: EffectivePolicySnapshot{
		PrincipalID:   "human-maintainer",
		PrincipalKind: kind,
		Status:        EffectiveActive,
		GrantRevision: 7,
		StateRevision: 12,
		RecoveryEpoch: 3,
		Grants:        []EffectiveGrant{{Role: role, AllowedAction: ActionExecute, Capability: "application.deploy", ResourceKind: "application", ResourceID: "app-test", Branch: BranchHuman}, {Role: role, AllowedAction: ActionAcknowledge, Capability: "application.deploy", ResourceKind: "application", ResourceID: "app-test", Branch: BranchHuman}},
	}})
}

func testPlan(operation string, branch Branch) generated.Plan {
	risk := RiskRoutine
	switch operation {
	case "application.deploy.production-like":
		risk = RiskProductionLike
	case "backup.restore", "resource.delete", "backup.retention.change":
		risk = RiskDestructive
	}
	return generated.Plan{
		PlanID:              "plan-test",
		PlanDigest:          "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Risk:                string(risk),
		AuthorizationBranch: string(branch),
		Binding:             generated.PlanBinding{StateRevision: 12, RecoveryEpoch: 3},
		Operations:          []generated.PlanOperation{{Sequence: 1, OperationID: "operation-test", OperationType: operation, TargetID: "app-test"}},
	}
}
