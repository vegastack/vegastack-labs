package authorization

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

// Sanitized reproducer preserves the production gate-plan shape and risk
// that ordinary approval rejected before evaluating its exact human grant.
const sanitizedNativeProfilePlan = `{"schema":"vegastack-labs.dev/plan","schemaVersion":"1.0.0","planId":"plan-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","planDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","declarationId":"gate-profile-synthetic-profile","binding":{"recoveryEpoch":0,"priorStateRevision":3,"stateRevision":4,"declarationRevision":2,"observationFingerprint":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","targetDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","reasonDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","policyVersion":"1.0.0","toolVersion":"0.0.0-test","contractVersion":"1.0.0"},"operations":[{"sequence":1,"operationId":"synthetic-profile","operationType":"gate.profile.bind","adapterId":"core.gate","executorId":"executor-central","targetId":"synthetic-profile","inputDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","artifactDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","idempotent":true}],"status":"planned","risk":"destructive","authorizationBranch":"human","executorMode":"central","executorId":null,"createdAt":"2026-01-01T00:00:00Z","expiresAt":"2026-01-01T00:30:00Z","readableDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","extensions":[]}`

func sanitizedGatePlan(t *testing.T) generated.Plan {
	t.Helper()
	raw := []byte(sanitizedNativeProfilePlan)
	var plan generated.Plan
	if err := generated.ValidateContractJSON(generated.SchemaIDPlan, raw, generated.ContractExact); err != nil {
		t.Fatal("invalid sanitized profile plan", err)
	}
	if err := json.Unmarshal(raw, &plan); err != nil {
		t.Fatal(err)
	}
	return plan
}

func TestGateRiskMatchesProducedProfileAndEvidencePlans(t *testing.T) {
	for _, operation := range []string{"gate.profile.bind", "gate.evidence.apply", "gate.evidence.supersede", "gate.evidence.revoke"} {
		t.Run(operation, func(t *testing.T) {
			plan := sanitizedGatePlan(t)
			plan.Operations[0].OperationType = operation
			if risk, err := ClassifyPlan(plan); err != nil || risk != RiskDestructive {
				t.Fatalf("owning gate plan risk rejected: %q %v", risk, err)
			}
			plan.Risk = string(RiskRoutine)
			if _, err := ClassifyPlan(plan); err == nil {
				t.Fatal("gate risk downgrade accepted")
			}
			if preauthorizedOperation(operation) {
				t.Fatal("gate operation became preauthorized")
			}
		})
	}
}

func TestGateRiskProfileUsesExactInitialHumanGrants(t *testing.T) {
	for _, action := range []Action{ActionAcknowledge, ActionExecute} {
		for _, variant := range []string{"exact", "unknown-operation", "wrong-grant", "stale-state", "wrong-epoch", "agent"} {
			t.Run(string(action)+"/"+variant, func(t *testing.T) {
				plan := sanitizedGatePlan(t)
				target := Target{Capability: "plan.acknowledge", ResourceKind: "plan-target", ResourceID: "synthetic-profile"}
				if action == ActionExecute {
					target = Target{Capability: "gate.profile.bind", ResourceKind: "execution-target", ResourceID: "synthetic-profile"}
				}
				grant := EffectiveGrant{Role: RoleControlPlaneAdmin, AllowedAction: action, Capability: target.Capability, ResourceKind: target.ResourceKind, ResourceID: target.ResourceID, Branch: BranchHuman}
				principal := identity.Principal{ID: "human-test", Method: identity.SlackSocketModeMethod, Kind: identity.PrincipalHuman}
				snapshot := EffectivePolicySnapshot{PrincipalKind: identity.PrincipalHuman, Status: EffectiveActive, GrantRevision: 1, StateRevision: 4, RecoveryEpoch: 0}
				switch variant {
				case "unknown-operation":
					plan.Operations[0].OperationType = "gate.profile.unknown"
				case "wrong-grant":
					grant.ResourceID = "other-profile"
				case "stale-state":
					snapshot.StateRevision++
				case "wrong-epoch":
					snapshot.RecoveryEpoch++
				case "agent":
					principal.Method = identity.LocalOSPeerMethod
					principal.Kind = identity.PrincipalAgent
					snapshot.PrincipalKind = identity.PrincipalAgent
				}
				snapshot.Grants = []EffectiveGrant{grant}
				evaluator := NewEvaluator(policyRepositoryStub{snapshot: snapshot})
				decision, err := evaluator.Authorize(context.Background(), principal, Request{Action: action, Target: target, Plan: &plan, Branches: []Branch{BranchHuman}})
				if err != nil || decision.Allowed != (variant == "exact" || variant == "agent" && action == ActionExecute) {
					t.Fatalf("sanitized gate authorization %s: %+v %v", variant, decision, err)
				}
			})
		}
	}
}
