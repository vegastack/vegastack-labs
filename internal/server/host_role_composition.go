package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/gate"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/store"
	"time"
)

type hostRoleComposition struct {
	gates  *store.GateRepository
	render func(context.Context, generated.LinuxRoleInput) (string, error)
	clock  func() time.Time
}

func (c hostRoleComposition) baseline(ctx context.Context, hostID string) (store.HostAdmissionSnapshot, error) {
	if c.gates == nil || c.clock == nil {
		return store.HostAdmissionSnapshot{}, actionFailure()
	}
	at := c.clock().UTC()
	s, err := c.gates.CheckHostAdmission(ctx, hostID, "role-install", at)
	if err != nil {
		return s, err
	}
	applied, err := c.gates.GetAppliedProfileScope(ctx)
	if err != nil {
		return s, err
	}
	if s.AppliedProfileDigest != hostaction.Digest(applied) {
		return s, actionFailure()
	}
	scope := gate.ResolvedScope{ProfileID: applied.ProfileID, ProfileVersion: applied.ProfileVersion, PolicyID: applied.PolicyID, PolicyVersion: applied.PolicyVersion, Capabilities: applied.Capabilities, StateRevision: applied.StateRevision, RecoveryEpoch: applied.RecoveryEpoch}
	evaluation, err := gate.EvaluateHostAdmission(ctx, s, scope, "host.hardening-baseline", at)
	if err != nil {
		return s, err
	}
	if evaluation.Outcome != "passed" {
		return s, actionFailure()
	}
	return s, nil
}
func (c hostRoleComposition) VerifyRoleBaseline(ctx context.Context, p generated.Plan) (store.HostAdmissionSnapshot, error) {
	if p.HostRoleScope == nil {
		return store.HostAdmissionSnapshot{}, actionFailure()
	}
	if p.HostAction != nil && (p.HostAction.ActionID == "debian.role.collect" || p.HostAction.ActionID == "debian.control.handoff.verify") {
		return c.gates.CheckHostAdmission(ctx, p.HostRoleScope.SubjectHostID, "role-install", c.clock().UTC())
	}
	return c.baseline(ctx, p.HostRoleScope.SubjectHostID)
}
func (c hostRoleComposition) PrepareRole(ctx context.Context, actionID string, in generated.LinuxRoleInput) (generated.LinuxRoleInput, error) {
	if c.gates == nil || c.clock == nil {
		return in, actionFailure()
	}
	var s store.HostAdmissionSnapshot
	var err error
	if actionID == "debian.role.collect" || actionID == "debian.control.handoff.verify" {
		s, err = c.gates.CheckHostAdmission(ctx, in.HostID, "role-install", c.clock().UTC())
	} else {
		s, err = c.baseline(ctx, in.HostID)
	}
	if err != nil {
		return in, err
	}
	if in.HostIdentityDigest != s.IdentityDigest || in.ProfileID != s.Profile.ProfileID || in.ProfileLockDigest != s.ProfileLockDigest || in.CurrentRoleBindingDigest != s.RoleBindingDigest {
		return in, actionFailure()
	}
	digest := store.HostAdmissionSnapshotDigest(s)
	if in.BaselineSnapshotDigest != "" && in.BaselineSnapshotDigest != digest {
		return in, actionFailure()
	}
	in.BaselineSnapshotDigest = digest
	if c.render == nil {
		return in, actionFailure()
	}
	in.RenderedPolicyDigest, err = c.render(ctx, in)
	return in, err
}
