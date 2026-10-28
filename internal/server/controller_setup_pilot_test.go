package server

import (
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/store"
	"strings"
	"testing"
	"time"
)

func controllerPilotFixture() (generated.ControllerSetupPilotPolicy, generated.Plan, store.GateAppliedProfile, store.Health, time.Time) {
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	d := "sha256:" + strings.Repeat("a", 64)
	q := generated.ControllerSetupPilotPolicy{Schema: generated.SchemaIDControllerSetupPilotPolicy, SchemaVersion: "1.0.0", HostID: "synthetic-controller", HostIdentityDigest: d, ControllerMachineIDDigest: d, ControllerInstanceID: "instance-a", AppliedProfileID: "profile-a", RecoveryEpoch: 0, RecoveryImageDigest: d, AdministratorUID: 1000, AdministratorPrincipalID: "operator-a", ServiceUID: 2000, ServiceGID: 2000, ExecutableDigest: d, ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)}
	p := generated.Plan{AuthorizationBranch: "human", ExecutorMode: "central", Binding: generated.PlanBinding{StateRevision: 3, RecoveryEpoch: 0}, Operations: []generated.PlanOperation{{OperationID: "controller-setup", AdapterID: "core.controller-setup", OperationType: "controller.setup.bootstrap", TargetID: q.HostID, ArtifactDigest: hostaction.Digest(q), InputDigest: d, ExecutorID: "executor-central", Idempotent: false}}}
	applied := store.GateAppliedProfile{ProfileID: q.AppliedProfileID, StateRevision: 2, RecoveryEpoch: 0, Capabilities: []string{controllerSetupPilotCapability(q)}}
	health := store.Health{Mode: store.DatabaseReady, IntegrityStatus: store.IntegrityVerified, Revision: store.RevisionToken{StateRevision: 3, RecoveryEpoch: 0}}
	return q, p, applied, health, now
}
func TestControllerPilotIsActualLocalEligibilityWithoutManagedHost(t *testing.T) {
	q, p, applied, health, now := controllerPilotFixture()
	got, e := verifyControllerSetupPilot(q, p, applied, q.ControllerInstanceID, q.ControllerMachineIDDigest, health, now)
	if e != nil || got.HostID != q.HostID || got.PolicyDigest != hostaction.Digest(q) || got.ControllerInstanceID != q.ControllerInstanceID || got.StateRevision != 3 || got.RecoveryImageDigest != q.RecoveryImageDigest {
		t.Fatalf("%+v %v", got, e)
	}
	raw, _ := json.Marshal(got)
	if e = generated.ValidateContractJSON(generated.SchemaIDControllerSetupPilotEligibility, raw, generated.ContractExact); e != nil {
		t.Fatal(e)
	}
	for _, word := range []string{"nativeQualification", "baselineSnapshot", "admissionQualified", "hostRoleScope"} {
		if strings.Contains(string(raw), word) {
			t.Fatal("eligibility fabricated admission", word)
		}
	}
}
func TestControllerPilotDeniesWrongPolicyAuthorityAndOrdinaryActions(t *testing.T) {
	for _, variant := range []string{"missing-capability", "generic-capability", "changed-policy", "wrong-profile", "wrong-instance", "wrong-machine", "stale-state", "wrong-epoch", "recovery-pending", "safe-mode", "expired", "unbounded-expiry", "admin-service-overlap", "protected-host", "no-human", "external-executor", "idempotent", "ordinary-role", "managed-host-projection", "unbound-initial", "invalid-input-digest"} {
		t.Run(variant, func(t *testing.T) {
			q, p, applied, health, now := controllerPilotFixture()
			instance, machine := q.ControllerInstanceID, q.ControllerMachineIDDigest
			switch variant {
			case "missing-capability":
				applied.Capabilities = nil
			case "generic-capability":
				applied.Capabilities = []string{"controller.setup.pilot"}
			case "changed-policy":
				q.RecoveryImageDigest = "sha256:" + strings.Repeat("b", 64)
			case "wrong-profile":
				applied.ProfileID = "other"
			case "wrong-instance":
				instance = "other"
			case "wrong-machine":
				machine = "sha256:" + strings.Repeat("b", 64)
			case "stale-state":
				health.Revision.StateRevision++
			case "wrong-epoch":
				health.Revision.RecoveryEpoch++
			case "recovery-pending":
				health.RecoveryPending = true
			case "safe-mode":
				health.Mode = "safe-mode"
			case "expired":
				now = now.Add(2 * time.Hour)
			case "unbounded-expiry":
				q.ExpiresAt = now.Add(48 * time.Hour).Format(time.RFC3339)
			case "admin-service-overlap":
				q.ServiceUID = q.AdministratorUID
			case "protected-host":
				q.HostID = "vsk-node-04"
			case "no-human":
				p.AuthorizationBranch = "preauthorized"
			case "external-executor":
				p.ExecutorMode = "external"
			case "idempotent":
				p.Operations[0].Idempotent = true
			case "ordinary-role":
				p.Operations[0].OperationType = "host.action.execute"
				p.Operations[0].AdapterID = "host-action"
			case "managed-host-projection":
				p.HostRoleScope = &generated.HostRoleScope{}
			case "invalid-input-digest":
				p.Operations[0].InputDigest = "not-a-digest"
			case "unbound-initial":
				p.HostAction = &generated.HostActionRequest{}
			}
			if _, e := verifyControllerSetupPilot(q, p, applied, instance, machine, health, now); e == nil {
				t.Fatal("invalid selection inherited pilot")
			}
		})
	}
}
func TestControllerPilotAbsentPolicyCannotEnableAnything(t *testing.T) {
	v := newControllerSetupPilotVerifier(nil, nil, nil, time.Now)
	if _, e := v.Verify(t.Context(), generated.Plan{}); e == nil {
		t.Fatal("missing protected source activated")
	}
}

func TestControllerPilotFreezesProtectedPolicy(t *testing.T) {
	q, _, _, _, _ := controllerPilotFixture()
	v := newControllerSetupPilotVerifier(nil, nil, &q, time.Now)
	before := v.policy.HostID
	q.HostID = "changed"
	if v.policy.HostID != before {
		t.Fatal("protected source aliased caller mutation")
	}
}
