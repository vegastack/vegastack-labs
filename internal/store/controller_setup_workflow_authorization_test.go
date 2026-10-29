package store

import (
	"context"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

type controllerWorkflowPolicy struct {
	snapshot authorization.EffectivePolicySnapshot
}

func (p controllerWorkflowPolicy) Snapshot(context.Context, string, authorization.Target) (authorization.EffectivePolicySnapshot, error) {
	return p.snapshot, nil
}

func controllerWorkflowDeclaration() generated.DeclarationRevision {
	return generated.DeclarationRevision{DeclarationType: "controller.setup", Status: "committed", Operations: []generated.DeclarationOperation{{Sequence: 1, OperationID: "foundation", AdapterID: "core.controller-setup", OperationType: "controller.setup.bootstrap", TargetID: "selected-controller", InputDigest: hostaction.Digest("input"), ArtifactDigest: hostaction.Digest("policy")}}}
}

func TestControllerSetupWorkflowOwnerUsesExactTargetGrants(t *testing.T) {
	for _, action := range []authorization.Action{authorization.ActionAuthor, authorization.ActionRead} {
		d := controllerWorkflowDeclaration()
		owners, err := workflowDeclarationTargets(nil, d, action)
		capability := "controller.setup.read"
		if action == authorization.ActionAuthor {
			capability = "controller.setup.prepare"
		}
		expected := authorization.Target{Capability: capability, ResourceKind: "controller-setup", ResourceID: "selected-controller"}
		if err != nil || len(owners) != 1 || owners[0] != expected {
			t.Fatalf("exact owner missing: %v %v", owners, err)
		}
		snapshot := authorization.EffectivePolicySnapshot{PrincipalID: "operator", PrincipalKind: identity.PrincipalHuman, Status: authorization.EffectiveActive, GrantRevision: 3, StateRevision: 21, RecoveryEpoch: 0, Grants: []authorization.EffectiveGrant{{Role: authorization.RoleControlPlaneAdmin, AllowedAction: action, Capability: capability, ResourceKind: expected.ResourceKind, ResourceID: expected.ResourceID}}}
		evaluator := authorization.NewEvaluator(controllerWorkflowPolicy{snapshot})
		for _, variant := range []string{"selected", "wrong-target", "wrong-actor"} {
			principal := identity.Principal{ID: "operator", Kind: identity.PrincipalHuman, Method: identity.LocalOSPeerMethod}
			target := owners[0]
			if variant == "wrong-target" {
				target.ResourceID = "another-controller"
			}
			if variant == "wrong-actor" {
				principal.ID = "another-operator"
			}
			got, e := evaluator.Authorize(context.Background(), principal, authorization.Request{Action: action, Target: target})
			if e != nil || got.Allowed != (variant == "selected") {
				t.Fatalf("%s %s: %v %v", action, variant, got, e)
			}
		}
	}
}

func TestControllerSetupWorkflowRejectsMalformedOwnership(t *testing.T) {
	mutations := map[string]func(*generated.DeclarationRevision){
		"multiple":          func(d *generated.DeclarationRevision) { d.Operations = append(d.Operations, d.Operations[0]) },
		"adapter":           func(d *generated.DeclarationRevision) { d.Operations[0].AdapterID = "other" },
		"operation":         func(d *generated.DeclarationRevision) { d.Operations[0].OperationType = "host.action" },
		"empty-target":      func(d *generated.DeclarationRevision) { d.Operations[0].TargetID = "" },
		"invalid-target":    func(d *generated.DeclarationRevision) { d.Operations[0].TargetID = "*" },
		"input":             func(d *generated.DeclarationRevision) { d.Operations[0].InputDigest = "invalid" },
		"artifact":          func(d *generated.DeclarationRevision) { d.Operations[0].ArtifactDigest = "invalid" },
		"idempotent":        func(d *generated.DeclarationRevision) { d.Operations[0].Idempotent = true },
		"sequence":          func(d *generated.DeclarationRevision) { d.Operations[0].Sequence = 2 },
		"offsite":           func(d *generated.DeclarationRevision) { d.Operations[0].OffsiteRunSpec = &generated.OffsiteRunSpec{} },
		"unrelated-payload": func(d *generated.DeclarationRevision) { d.NetworkEndpoint = &generated.NetworkEndpointRequest{} },
		"deleted":           func(d *generated.DeclarationRevision) { d.Status = "deleted" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			d := controllerWorkflowDeclaration()
			mutate(&d)
			owners, err := workflowDeclarationTargets(nil, d, authorization.ActionAuthor)
			if err == nil || len(owners) != 0 {
				t.Fatalf("malformed owner accepted: %v %v", owners, err)
			}
		})
	}
}
