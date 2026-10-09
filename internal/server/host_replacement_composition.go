package server

import (
	"context"
	"time"

	"github.com/vegastack/vegastack-labs/internal/gate"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostreplacement"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type hostReplacementComposition struct {
	authority  *store.Store
	repository *store.HostReplacementRepository
	gates      *store.GateRepository
	clock      func() time.Time
}

func (c hostReplacementComposition) roleAdmission(ctx context.Context, hostID string) (store.HostAdmissionSnapshot, error) {
	if c.gates == nil || c.clock == nil {
		return store.HostAdmissionSnapshot{}, actionFailure()
	}
	at := c.clock().UTC()
	snapshot, err := c.gates.CheckHostAdmission(ctx, hostID, "workload-admit", at)
	if err != nil {
		return snapshot, err
	}
	applied, err := c.gates.GetAppliedProfileScope(ctx)
	if err != nil {
		return snapshot, err
	}
	if snapshot.AppliedProfileDigest != hostaction.Digest(applied) {
		return snapshot, actionFailure()
	}
	scope := gate.ResolvedScope{ProfileID: applied.ProfileID, ProfileVersion: applied.ProfileVersion, PolicyID: applied.PolicyID, PolicyVersion: applied.PolicyVersion, Capabilities: applied.Capabilities, StateRevision: applied.StateRevision, RecoveryEpoch: applied.RecoveryEpoch}
	decision, err := gate.EvaluateHostAdmission(ctx, snapshot, scope, "host.role-admission", at)
	if err != nil {
		return snapshot, err
	}
	if decision.Outcome != "passed" {
		return snapshot, actionFailure()
	}
	return snapshot, nil
}
func replacementResultDigest(p generated.Plan, x store.HostReplacementExecution) string {
	return hostaction.Digest(struct{ PlanID, PlanDigest, RunID, StepID, LeaseID string }{p.PlanID, p.PlanDigest, x.RunID, x.StepID, x.LeaseID})
}
func (c hostReplacementComposition) ApplyReplacement(ctx context.Context, p generated.Plan, x store.HostReplacementExecution) (string, error) {
	if c.authority == nil || c.repository == nil || c.clock == nil || len(p.Operations) != 1 {
		return "", actionFailure()
	}
	bound, err := c.authority.HostRunReadContext(ctx, x.RunID)
	if err != nil {
		return "", err
	}
	switch p.Operations[0].OperationType {
	case hostreplacement.FreezeOperation:
		if p.HostReplacement == nil {
			return "", actionFailure()
		}
		_, err = c.repository.Freeze(bound, x)
	case hostreplacement.AliasClaimOperation:
		if p.HostAliasClaim == nil {
			return "", actionFailure()
		}
		var snapshot store.HostAdmissionSnapshot
		snapshot, err = c.roleAdmission(bound, p.HostAliasClaim.HostID)
		if err == nil {
			_, err = c.repository.ClaimAliases(bound, x, snapshot)
		}
	case hostreplacement.CommitOperation:
		if p.HostReplacement == nil {
			return "", actionFailure()
		}
		var snapshot store.HostAdmissionSnapshot
		snapshot, err = c.roleAdmission(bound, p.HostReplacement.NewHostID)
		if err == nil && (snapshot.IdentityDigest != p.HostReplacement.NewIdentityDigest || snapshot.RoleBindingDigest != p.HostReplacement.ProposedRoleBindingDigest || snapshot.ProfileLockDigest != p.HostReplacement.ProfileLockDigest) {
			err = actionFailure()
		}
		if err == nil {
			_, err = verifyReplacementFences(bound, c.repository, x, c.clock().UTC())
		}
		if err == nil {
			_, err = c.repository.Commit(bound, store.HostReplacementCommit{Execution: x, Admission: snapshot})
		}
	default:
		return "", actionFailure()
	}
	if err != nil {
		return "", err
	}
	return replacementResultDigest(p, x), nil
}
func (c hostReplacementComposition) VerifyReplacement(ctx context.Context, p generated.Plan, x store.HostReplacementExecution, digest string) error {
	if c.authority == nil || c.repository == nil || len(p.Operations) != 1 || digest != replacementResultDigest(p, x) {
		return actionFailure()
	}
	bound, err := c.authority.HostRunReadContext(ctx, x.RunID)
	if err != nil {
		return err
	}
	return c.repository.VerifyExecution(bound, x, p.Operations[0].OperationType)
}
