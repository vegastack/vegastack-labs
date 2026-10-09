package authorization

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"testing"
)

func TestRecoveryReceiveAcknowledgementIncludesExactFrozenSource(t *testing.T) {
	d := generated.ControlRecoveryReceiveInput{Schema: generated.SchemaIDControlRecoveryReceiveInput, SchemaVersion: "1.0.0", Binding: generated.RestoreBinding{FormerHostID: "old-host", ReplacementHostID: "new-host"}, Replacement: generated.HostReplacementRequest{OldHostID: "old-host", NewHostID: "new-host"}}
	raw, _ := json.Marshal(d)
	p := testPlan("host.action.execute", BranchHuman)
	p.Risk = string(RiskInfrastructure)
	p.Operations[0].TargetID = "new-host"
	p.HostAction = &generated.HostActionRequest{ActionID: hostaction.RecoveryReceiveAction, ActionVersion: "1.0.0", HostID: "new-host", ActionInput: string(raw), ActionInputDigest: hostaction.BytesDigest(raw)}
	target := Target{Capability: "plan.acknowledge", ResourceKind: "plan-target", ResourceID: "old-host"}
	evaluator := NewEvaluator(policyRepositoryStub{snapshot: EffectivePolicySnapshot{PrincipalKind: identity.PrincipalHuman, Status: EffectiveActive, GrantRevision: 7, StateRevision: p.Binding.StateRevision, RecoveryEpoch: p.Binding.RecoveryEpoch, Grants: []EffectiveGrant{{Role: RoleControlPlaneAdmin, AllowedAction: ActionAcknowledge, Capability: target.Capability, ResourceKind: target.ResourceKind, ResourceID: target.ResourceID, Branch: BranchHuman}}}})
	decision, err := evaluator.Authorize(context.Background(), identity.Principal{ID: "human-control", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}, Request{Action: ActionAcknowledge, Target: target, Plan: &p, Branches: []Branch{BranchHuman}})
	if err != nil || !decision.Allowed {
		t.Fatalf("frozen source excluded: reason=%s err=%v", decision.ReasonCode, err)
	}
	for _, variant := range []string{"unrelated", "action", "altered-input", "binding"} {
		t.Run(variant, func(t *testing.T) {
			q := p
			a := *p.HostAction
			q.HostAction = &a
			id := "old-host"
			switch variant {
			case "unrelated":
				id = "other-host"
			case "action":
				a.ActionID = "debian.access.collect"
			case "altered-input":
				a.ActionInput += " "
			case "binding":
				changed := d
				changed.Binding.FormerHostID = "other-host"
				b, _ := json.Marshal(changed)
				a.ActionInput = string(b)
				a.ActionInputDigest = hostaction.BytesDigest(b)
			}
			if planContainsTarget(q, id) {
				t.Fatal("unbound source admitted")
			}
		})
	}
}
