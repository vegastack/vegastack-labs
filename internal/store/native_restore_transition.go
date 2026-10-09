package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

// nativeVerifiedRestoreBinding resolves the one actual authority transition,
// before alias commit, so fresh current-epoch qualification can break the
// restore/admission cycle. It never carries prior-epoch qualification forward.
func nativeVerifiedRestoreBinding(ctx context.Context, q nativeQuery) (*generated.RestoreBinding, error) {
	var plan, request, binding, continuity []byte
	var b RecoveredAuthorityBundle
	var digest, instance, canaryDigest string
	var epoch int64
	err := q.row(`SELECT b.plan_bytes,b.readable_plan,b.request_bytes,b.binding_bytes,b.continuity_bytes,b.status,b.bundle_digest,m.instance_id,m.recovery_epoch,v.evidence_digest FROM system_meta m JOIN recovery_authority_journal v ON v.instance_id=m.instance_id AND v.recovery_epoch=m.recovery_epoch AND v.transition='verified' JOIN recovery_authority_journal p ON p.plan_id=v.plan_id AND p.plan_digest=v.plan_digest AND p.binding_bytes=v.binding_bytes AND p.transition='promoted' AND p.candidate_digest=v.candidate_digest AND p.fence_set_digest=v.fence_set_digest AND p.audit_decision_digest=v.audit_decision_digest AND p.instance_id=v.instance_id AND p.recovery_epoch=v.recovery_epoch JOIN recovery_authority_bundles b ON b.plan_id=v.plan_id AND b.plan_digest=v.plan_digest AND b.binding_bytes=v.binding_bytes WHERE m.id=1 AND m.authority_mode='ready' ORDER BY v.created_at DESC,v.plan_id LIMIT 1`).Scan(&plan, &b.Readable, &request, &binding, &continuity, &b.Status, &digest, &instance, &epoch, &canaryDigest)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if json.Unmarshal(plan, &b.Plan) != nil || json.Unmarshal(request, &b.Request) != nil || json.Unmarshal(binding, &b.Binding) != nil {
		return nil, nativeError()
	}
	if len(continuity) > 0 {
		var c HostReplacementContinuity
		if json.Unmarshal(continuity, &c) != nil {
			return nil, nativeError()
		}
		b.ReplacementContinuity = &c
	}
	_, _, _, actual, err := validateRecoveredAuthorityBundle(b)
	if err != nil || actual != digest || b.Binding.NewInstanceID != instance || b.Binding.NextRecoveryEpoch != epoch || b.Binding.PriorInstanceID == instance || b.Binding.NextRecoveryEpoch != b.Binding.PriorRecoveryEpoch+1 || !restoreDigest(canaryDigest) {
		return nil, nativeError()
	}
	if b.ReplacementContinuity != nil {
		if err := verifyReplacementContinuityRows(ctx, q.tx, *b.ReplacementContinuity); err != nil {
			return nil, err
		}
	}
	var event int64
	var result string
	r := b.Binding
	err = q.row(`SELECT a.event_id,c.result_digest FROM recovery_canary_runs c JOIN audit_events a ON a.correlation_id=c.run_id AND a.event_type='recovery.canary-noop-verified' AND a.target_kind='recovery' AND a.target_id=c.instance_id AND a.recovery_epoch=c.recovery_epoch AND a.state_revision=c.state_revision WHERE c.plan_id=? AND c.plan_digest=? AND c.run_id=? AND c.step_id=? AND c.lease_id=? AND c.instance_id=? AND c.recovery_epoch=?`, r.PlanID, r.PlanDigest, r.CanaryRunID, r.CanaryStepID, r.CanaryLeaseID, instance, epoch).Scan(&event, &result)
	if err != nil || event <= 0 || !restoreDigest(result) {
		return nil, nativeError()
	}
	// The validated immutable bundle, rather than caller JSON, supplies origin.
	if hostaction.Digest(r) != hostaction.BytesDigest(binding) {
		return nil, nativeError()
	}
	return &r, nil
}
