package server

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
	"regexp"
	"slices"
	"time"
)

// This selected local controller need not be a managed host. Eligibility is
// deliberately distinct from a HostAdmissionSnapshot and cannot qualify gates.
var controllerSetupDigest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

type controllerSetupPilotVerifier struct {
	authority *store.Store
	gates     *store.GateRepository
	policy    *generated.ControllerSetupPilotPolicy
	clock     func() time.Time
	machine   func() (string, error)
}

func newControllerSetupPilotVerifier(authority *store.Store, gates *store.GateRepository, policy *generated.ControllerSetupPilotPolicy, clock func() time.Time) *controllerSetupPilotVerifier {
	if policy != nil {
		copy := *policy
		policy = &copy
	}
	return &controllerSetupPilotVerifier{authority: authority, gates: gates, policy: policy, clock: clock, machine: pilotMachineDigest}
}
func controllerSetupPilotCapability(p generated.ControllerSetupPilotPolicy) string {
	return "controller.setup.pilot." + hostaction.Digest(p)[7:]
}
func controllerSetupMarker(raw string) (string, error) {
	var marker struct {
		Digest string `json:"controllerSetupPilotDigest"`
	}
	if json.Unmarshal([]byte(raw), &marker) != nil {
		return "", actionFailure()
	}
	return marker.Digest, nil
}
func (v *controllerSetupPilotVerifier) Verify(ctx context.Context, p generated.Plan) (generated.ControllerSetupPilotEligibility, error) {
	var zero generated.ControllerSetupPilotEligibility
	if v == nil || v.authority == nil || v.gates == nil || v.policy == nil || v.clock == nil || v.machine == nil {
		return zero, actionFailure()
	}
	health, e := v.authority.Health(ctx)
	if e != nil {
		return zero, e
	}
	authority, e := v.authority.CurrentAuthority(ctx)
	if e != nil {
		return zero, e
	}
	applied, e := v.gates.GetAppliedProfileScope(ctx)
	if e != nil {
		return zero, e
	}
	machine, e := v.machine()
	if e != nil {
		return zero, e
	}
	return verifyControllerSetupPilot(*v.policy, p, applied, authority.InstanceID, machine, health, v.clock().UTC())
}
func verifyControllerSetupPilot(policy generated.ControllerSetupPilotPolicy, p generated.Plan, applied store.GateAppliedProfile, instance, machine string, health store.Health, now time.Time) (generated.ControllerSetupPilotEligibility, error) {
	var zero generated.ControllerSetupPilotEligibility
	expiry, e := time.Parse(time.RFC3339, policy.ExpiresAt)
	if !serverconfig.ValidControllerSetupPilot(policy) || e != nil || now.IsZero() || !now.Before(expiry) || expiry.Sub(now) > 24*time.Hour || p.AuthorizationBranch != "human" || p.ExecutorMode != "central" || p.HostRoleScope != nil || p.HostAccessSequence != nil || len(p.Operations) != 1 || health.Mode != store.DatabaseReady || health.RecoveryPending || health.IntegrityStatus != store.IntegrityVerified {
		return zero, actionFailure()
	}
	digest := hostaction.Digest(policy)
	if !slices.Contains(applied.Capabilities, controllerSetupPilotCapability(policy)) || applied.ProfileID != policy.AppliedProfileID || applied.RecoveryEpoch != policy.RecoveryEpoch || applied.StateRevision > health.Revision.StateRevision || instance != policy.ControllerInstanceID || machine != policy.ControllerMachineIDDigest || health.Revision.RecoveryEpoch != policy.RecoveryEpoch || p.Binding.StateRevision != health.Revision.StateRevision || p.Binding.RecoveryEpoch != health.Revision.RecoveryEpoch {
		return zero, actionFailure()
	}
	op := p.Operations[0]
	if op.TargetID != policy.HostID || op.Idempotent {
		return zero, actionFailure()
	}
	switch {
	case op.AdapterID == "core.controller-setup" && op.OperationType == "controller.setup.bootstrap":
		// The bootstrap planner binds the complete fixed installer request in
		// InputDigest. This distinct class must never enter the managed-host draft.
		if p.HostAction != nil || op.ArtifactDigest != digest || !controllerSetupDigest.MatchString(op.InputDigest) {
			return zero, actionFailure()
		}
	case op.AdapterID == hostaction.AdapterID && op.OperationType == hostaction.OperationType:
		r := p.HostAction
		if r == nil || r.ActionID != "cloudflare.connector.install" || r.ActionVersion != "1.0.0" || hostaction.ValidateRequest(*r) != nil || r.HostID != policy.HostID || r.ConsoleConfirmation.HostIdentityDigest != policy.HostIdentityDigest || r.RecoveryEpoch != policy.RecoveryEpoch || r.ExpectedStateRevision != health.Revision.StateRevision || op.ArtifactDigest != hostaction.Digest(*r) {
			return zero, actionFailure()
		}
		marker, e := controllerSetupMarker(r.ActionInput)
		if e != nil || marker != digest {
			return zero, actionFailure()
		}
	default:
		return zero, actionFailure()
	}
	// This is selection/current-authority evidence only. Claim/receipt must still
	// check the acknowledged run/lease, preserved image and actual OS pre/postimages.
	return generated.ControllerSetupPilotEligibility{Schema: generated.SchemaIDControllerSetupPilotEligibility, SchemaVersion: "1.0.0", HostID: policy.HostID, HostIdentityDigest: policy.HostIdentityDigest, ControllerMachineIDDigest: machine, ControllerInstanceID: instance, PolicyDigest: digest, StateRevision: health.Revision.StateRevision, RecoveryEpoch: health.Revision.RecoveryEpoch, AdministratorUID: policy.AdministratorUID, AdministratorPrincipalID: policy.AdministratorPrincipalID, ServiceUID: policy.ServiceUID, ServiceGID: policy.ServiceGID, RecoveryImageDigest: policy.RecoveryImageDigest}, nil
}
