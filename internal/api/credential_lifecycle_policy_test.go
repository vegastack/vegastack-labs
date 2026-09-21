package api

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/result"
)

type lifecyclePolicySnapshot struct {
	snapshot authorization.EffectivePolicySnapshot
}

func (repository lifecyclePolicySnapshot) Snapshot(_ context.Context, principalID string, _ authorization.Target) (authorization.EffectivePolicySnapshot, error) {
	snapshot := repository.snapshot
	snapshot.PrincipalID = principalID
	return snapshot, nil
}

type lifecycleDecisionRecorder struct{}

func (lifecycleDecisionRecorder) RecordDecision(context.Context, authorization.DecisionRecord) error {
	return nil
}

func lifecycleExecutionApp(snapshot authorization.EffectivePolicySnapshot) *Application {
	factory := result.NewFactory(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}, func() (string, error) { return "lifecycle-decision", nil })
	return &Application{config: Config{Results: factory}, effective: EffectiveAuthorizationConfig{Authorizer: authorization.NewEvaluator(lifecyclePolicySnapshot{snapshot}), Recorder: lifecycleDecisionRecorder{}, Clock: func() time.Time { return time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC) }}}
}

func lifecycleExecutionPlan(action string) generated.Plan {
	plan := apiAuthorizationPlan(authorization.BranchHuman)
	plan.Risk = string(authorization.RiskControlPlane)
	plan.Operations[0].OperationType = action
	plan.Operations[0].TargetID = "target-lifecycle"
	return plan
}

func TestCredentialLifecycleAuthorizeRunPlanRequiresExactActionScopedGrant(t *testing.T) {
	for _, action := range []string{"credential.stage", "credential.activate", "credential.rotate", "credential.revoke", "credential.recover"} {
		t.Run(action, func(t *testing.T) {
			principal := identity.Principal{ID: "human-lifecycle", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}
			plan := lifecycleExecutionPlan(action)
			exact := authorization.EffectiveGrant{Role: authorization.RoleControlPlaneAdmin, AllowedAction: authorization.ActionExecute, Capability: action, ResourceKind: "execution-target", ResourceID: "target-lifecycle", Branch: authorization.BranchHuman}
			for _, test := range []struct {
				name   string
				grant  authorization.EffectiveGrant
				allows bool
			}{
				{"exact", exact, true},
				{"generic plan execute", authorization.EffectiveGrant{Role: exact.Role, AllowedAction: exact.AllowedAction, Capability: "plan.execute", ResourceKind: "plan-target", ResourceID: exact.ResourceID, Branch: exact.Branch}, false},
				{"wrong action", authorization.EffectiveGrant{Role: exact.Role, AllowedAction: exact.AllowedAction, Capability: "credential.unknown", ResourceKind: exact.ResourceKind, ResourceID: exact.ResourceID, Branch: exact.Branch}, false},
				{"wrong kind", authorization.EffectiveGrant{Role: exact.Role, AllowedAction: exact.AllowedAction, Capability: exact.Capability, ResourceKind: "plan-target", ResourceID: exact.ResourceID, Branch: exact.Branch}, false},
				{"wrong target", authorization.EffectiveGrant{Role: exact.Role, AllowedAction: exact.AllowedAction, Capability: exact.Capability, ResourceKind: exact.ResourceKind, ResourceID: "other-target", Branch: exact.Branch}, false},
				{"wrong branch", authorization.EffectiveGrant{Role: exact.Role, AllowedAction: exact.AllowedAction, Capability: exact.Capability, ResourceKind: exact.ResourceKind, ResourceID: exact.ResourceID, Branch: authorization.BranchPreauthorized}, false},
				{"infrastructure admin", authorization.EffectiveGrant{Role: authorization.RoleInfrastructureAdmin, AllowedAction: exact.AllowedAction, Capability: exact.Capability, ResourceKind: exact.ResourceKind, ResourceID: exact.ResourceID, Branch: exact.Branch}, false},
				{"author", authorization.EffectiveGrant{Role: authorization.RoleAuthor, AllowedAction: exact.AllowedAction, Capability: exact.Capability, ResourceKind: exact.ResourceKind, ResourceID: exact.ResourceID, Branch: exact.Branch}, false},
			} {
				t.Run(test.name, func(t *testing.T) {
					app := lifecycleExecutionApp(authorization.EffectivePolicySnapshot{PrincipalKind: principal.Kind, Status: authorization.EffectiveActive, GrantRevision: 1, StateRevision: plan.Binding.StateRevision, RecoveryEpoch: plan.Binding.RecoveryEpoch, Grants: []authorization.EffectiveGrant{test.grant}})
					req := httptest.NewRequest("POST", "/v1/runs", nil)
					req = req.WithContext(identity.WithVerifiedPrincipal(req.Context(), principal))
					decision, err := app.authorizeRunPlan(req, plan)
					if test.allows {
						if err != nil || !decision.Allowed || decision.Action != "execute" || decision.TargetID != "target-lifecycle" {
							t.Fatalf("exact execution denied: %+v %v", decision, err)
						}
					} else if err == nil {
						t.Fatalf("incorrect execution grant allowed: %+v", decision)
					}
				})
			}
		})
	}
}

func TestCredentialLifecycleAgentCannotAcknowledgeButExactAgentCanExecute(t *testing.T) {
	agent := identity.Principal{ID: "agent-lifecycle", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalAgent}
	plan := lifecycleExecutionPlan("credential.stage")
	exact := authorization.EffectiveGrant{Role: authorization.RoleControlPlaneAdmin, AllowedAction: authorization.ActionExecute, Capability: "credential.stage", ResourceKind: "execution-target", ResourceID: "target-lifecycle", Branch: authorization.BranchHuman}
	app := lifecycleExecutionApp(authorization.EffectivePolicySnapshot{PrincipalKind: agent.Kind, Status: authorization.EffectiveActive, GrantRevision: 1, StateRevision: plan.Binding.StateRevision, RecoveryEpoch: plan.Binding.RecoveryEpoch, Grants: []authorization.EffectiveGrant{exact}})
	req := httptest.NewRequest("POST", "/v1/runs", nil)
	req = req.WithContext(identity.WithVerifiedPrincipal(req.Context(), agent))
	if decision, err := app.authorizeRunPlan(req, plan); err != nil || !decision.Allowed {
		t.Fatalf("exact agent execution denied: %+v %v", decision, err)
	}
	ackGrant := authorization.EffectiveGrant{Role: authorization.RoleControlPlaneAdmin, AllowedAction: authorization.ActionAcknowledge, Capability: "plan.acknowledge", ResourceKind: "plan-target", ResourceID: "target-lifecycle", Branch: authorization.BranchHuman}
	ack := authorization.NewEvaluator(lifecyclePolicySnapshot{authorization.EffectivePolicySnapshot{PrincipalKind: agent.Kind, Status: authorization.EffectiveActive, GrantRevision: 1, StateRevision: plan.Binding.StateRevision, RecoveryEpoch: plan.Binding.RecoveryEpoch, Grants: []authorization.EffectiveGrant{ackGrant}}})
	decision, err := ack.Authorize(context.Background(), agent, authorization.Request{Action: authorization.ActionAcknowledge, Target: authorization.Target{Capability: "plan.acknowledge", ResourceKind: "plan-target", ResourceID: "target-lifecycle"}, Plan: &plan, Branches: []authorization.Branch{authorization.BranchHuman}})
	if err != nil || decision.Allowed || decision.ReasonCode != authorization.ReasonAgentCannotAcknowledge {
		t.Fatalf("agent acknowledgement = %+v %v", decision, err)
	}
}
