package store

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

// The existing durable intent is the desired role binding. It is visible before
// remote effects, including when the caller loses the connection. No successful
// result is synthesized; the common evaluator still requires fresh observations.
func admissionRoleBinding(ctx context.Context, tx ReadTx, out *HostAdmissionSnapshot) error {
	rows, err := tx.query(ctx, `SELECT p.canonical_bytes,p.readable_plan FROM immutable_plans p JOIN plan_runs r ON r.plan_id=p.plan_id AND r.plan_digest=p.plan_digest JOIN plan_run_steps s ON s.run_id=r.run_id WHERE r.recovery_epoch=? AND s.target_id=? AND s.effect_state IN ('intent-recorded','receipt-recorded','effect-unknown','verified') AND json_extract(p.canonical_bytes,'$.hostAction.actionId') IN ('debian.role.apply','debian.control.handoff') ORDER BY p.state_revision DESC,p.plan_id DESC LIMIT 1`, out.Revision.RecoveryEpoch, out.Host.HostID)
	if err != nil {
		return err
	}
	defer rows.Close()
	if !rows.Next() {
		return rows.Err()
	}
	var raw []byte
	var readable string
	var p generated.Plan
	if rows.Scan(&raw, &readable) != nil || json.Unmarshal(raw, &p) != nil || !validPlanDigests(p, readable) || p.HostRoleScope == nil {
		return actionError(generated.ErrorCodeIntegrityFailure)
	}
	s := p.HostRoleScope
	if s.SubjectHostID != out.Host.HostID || s.SubjectIdentityDigest != out.IdentityDigest || s.ProfileLockDigest != out.ProfileLockDigest {
		out.Blockers = append(out.Blockers, "host-binding-changed")
		return nil
	}
	out.RoleBindingDigest = s.RoleBindingDigest
	out.RoleIntentRevision = p.Binding.StateRevision
	out.NetworkingRequired = s.NetworkingRequired
	out.StandbyRequired = s.StandbyRequired
	out.Profile.RoleID = s.RoleID
	return nil
}

// HostAdmissionSnapshotDigest binds the exact server-resolved proof set. This is
// an inert digest, never a readiness decision or client-provided qualification.
func HostAdmissionSnapshotDigest(s HostAdmissionSnapshot) string { return hostAdmissionProofDigest(s) }
