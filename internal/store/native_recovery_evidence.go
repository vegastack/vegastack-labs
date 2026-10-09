package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostreplacement"
)

// NativeReplacementRecoveryEvidence is an internal projection of the completed
// recovery canary and subsequent alias CAS. CanaryDigest is the actual digest
// persisted by EnableRecoveredAuthority; no missing canary flags are invented.
type NativeReplacementRecoveryEvidence struct {
	CurrentProfileID         string
	CurrentProfileLockDigest string
	Binding                  generated.RestoreBinding
	Replacement              generated.HostReplacementState
	Continuity               generated.HostReplacementContinuityReference
	CanaryDigest             string
	CanaryRunID              string
	CanaryEventID            int64
	VerifiedAt               string
}

func (r *GateRepository) nativeReplacementRecoveryEvidence(ctx context.Context, q nativeQuery, e NativeProducerExecution) (*NativeReplacementRecoveryEvidence, error) {
	deny := func() (*NativeReplacementRecoveryEvidence, error) { return nil, nativeError() }
	p, ref := e.Plan, e.Reference
	request := p.HostReplacement
	if request == nil || request.Operation != "commit" || request.RestorationClass != "control-database" || request.NewHostID != ref.HostID || e.Receipt.Status != "succeeded" {
		return deny()
	}
	event, _, err := readReplacementEvent(q.row, request.ReplacementID)
	if err != nil || event.Type != "committed" || event.Execution.PlanID != p.PlanID || event.Execution.PlanDigest != p.PlanDigest || event.Execution.RunID != ref.RunID || event.Execution.StepID != ref.StepID || event.Execution.LeaseID != ref.LeaseID || event.State.RestorePlanID == nil || event.State.Status != "committed" {
		return deny()
	}
	state := event.State
	if state.OldHostID != request.OldHostID || state.NewHostID != request.NewHostID || state.OldIdentityDigest != request.OldIdentityDigest || state.NewIdentityDigest != request.NewIdentityDigest || state.RecoveryEpoch != p.Binding.RecoveryEpoch {
		return deny()
	}
	var identity, instance, mode string
	var epoch int64
	if q.row(`SELECT identity_digest FROM managed_hosts WHERE host_id=?`, ref.HostID).Scan(&identity) != nil || identity != request.NewIdentityDigest || q.row(`SELECT instance_id,recovery_epoch,authority_mode FROM system_meta WHERE id=1`).Scan(&instance, &epoch, &mode) != nil || mode != "ready" || epoch != p.Binding.RecoveryEpoch {
		return deny()
	}
	var originalID string
	if q.row(`SELECT draft_id FROM host_replacement_drafts WHERE replacement_id=? AND operation='freeze'`, request.ReplacementID).Scan(&originalID) != nil {
		return deny()
	}
	original, err := readReplacementDraft(q.row, originalID)
	if err != nil || original.BindingDigest != state.BindingDigest {
		return deny()
	}
	if validateReplacementRoleIntent(q.row, *request, state.RoleIntentRevision) != nil {
		return deny()
	}
	var roleRaw []byte
	var roleReadable string
	var rolePlan generated.Plan
	if q.row(`SELECT p.canonical_bytes,p.readable_plan FROM immutable_plans p JOIN plan_runs r ON r.plan_id=p.plan_id AND r.plan_digest=p.plan_digest JOIN plan_run_steps s ON s.run_id=r.run_id WHERE p.declaration_id=? AND p.state_revision=? AND p.recovery_epoch=? AND r.status='succeeded' AND s.status='succeeded' AND s.effect_state='verified' AND s.target_id=?`, request.ProposedRoleDeclarationID, state.RoleIntentRevision, epoch, request.NewHostID).Scan(&roleRaw, &roleReadable) != nil || json.Unmarshal(roleRaw, &rolePlan) != nil || !validPlanDigests(rolePlan, roleReadable) || rolePlan.HostRoleScope == nil || rolePlan.HostRoleScope.ProfileID != request.ProfileID || rolePlan.HostRoleScope.ProfileLockDigest != request.ProfileLockDigest {
		return deny()
	}
	var planRaw, requestRaw, bindingRaw, continuityRaw []byte
	var bundle RecoveredAuthorityBundle
	var storedDigest, canaryDigest, verifiedAt string
	if q.row(`SELECT b.plan_bytes,b.readable_plan,b.request_bytes,b.binding_bytes,b.continuity_bytes,b.status,b.bundle_digest,v.evidence_digest,v.created_at FROM recovery_authority_bundles b JOIN recovery_authority_journal v ON v.plan_id=b.plan_id AND v.plan_digest=b.plan_digest AND v.binding_bytes=b.binding_bytes AND v.transition='verified' JOIN recovery_authority_journal p ON p.plan_id=v.plan_id AND p.plan_digest=v.plan_digest AND p.binding_bytes=v.binding_bytes AND p.transition='promoted' AND p.candidate_digest=v.candidate_digest AND p.fence_set_digest=v.fence_set_digest AND p.audit_decision_digest=v.audit_decision_digest AND p.instance_id=v.instance_id AND p.recovery_epoch=v.recovery_epoch WHERE b.plan_id=? AND v.instance_id=? AND v.recovery_epoch=?`, *state.RestorePlanID, instance, epoch).Scan(&planRaw, &bundle.Readable, &requestRaw, &bindingRaw, &continuityRaw, &bundle.Status, &storedDigest, &canaryDigest, &verifiedAt) != nil {
		return deny()
	}
	var continuity HostReplacementContinuity
	if json.Unmarshal(planRaw, &bundle.Plan) != nil || json.Unmarshal(requestRaw, &bundle.Request) != nil || json.Unmarshal(bindingRaw, &bundle.Binding) != nil || json.Unmarshal(continuityRaw, &continuity) != nil {
		return deny()
	}
	bundle.ReplacementContinuity = &continuity
	_, _, _, digest, err := validateRecoveredAuthorityBundle(bundle)
	b := bundle.Binding
	if err != nil || digest != storedDigest || validateReplacementContinuity(continuity) != nil || verifyReplacementContinuityRows(ctx, q.tx, continuity) != nil || hostreplacement.BindRestore(original.Request, b) != nil || b.NewInstanceID != instance || b.NextRecoveryEpoch != epoch || b.NextRecoveryEpoch != b.PriorRecoveryEpoch+1 || b.PriorInstanceID == b.NewInstanceID || state.RestorationReceiptDigest != hostaction.Digest(b) || state.ContinuityDigest != continuity.Reference.Digest || !restoreDigest(canaryDigest) {
		return deny()
	}
	if _, err := time.Parse(time.RFC3339, verifiedAt); err != nil {
		return deny()
	}
	var eventID int64
	var resultDigest string
	if q.row(`SELECT a.event_id,c.result_digest FROM recovery_canary_runs c JOIN audit_events a ON a.correlation_id=c.run_id AND a.event_type='recovery.canary-noop-verified' AND a.target_kind='recovery' AND a.target_id=c.instance_id AND a.recovery_epoch=c.recovery_epoch AND a.state_revision=c.state_revision WHERE c.plan_id=? AND c.plan_digest=? AND c.run_id=? AND c.step_id=? AND c.lease_id=? AND c.instance_id=? AND c.recovery_epoch=? AND a.occurred_at<=?`, b.PlanID, b.PlanDigest, b.CanaryRunID, b.CanaryStepID, b.CanaryLeaseID, instance, epoch, verifiedAt).Scan(&eventID, &resultDigest) != nil || eventID <= 0 || !restoreDigest(resultDigest) {
		return deny()
	}
	if len(state.AliasBindings) != len(request.AliasBindings) || len(state.AliasBindings) == 0 {
		return deny()
	}
	for _, alias := range state.AliasBindings {
		var raw []byte
		var digest string
		if q.row(`SELECT h.event_bytes,h.event_digest FROM host_alias_owners o JOIN host_alias_history h ON h.event_digest=o.event_digest AND h.alias_id=o.alias_id AND h.owner_host_id=o.owner_host_id AND h.owner_identity_digest=o.owner_identity_digest AND h.owner_revision=o.owner_revision AND h.ownership_generation=o.ownership_generation WHERE o.alias_id=? AND o.owner_host_id=? AND o.owner_identity_digest=? AND o.owner_revision=? AND o.ownership_generation=? AND o.frozen_replacement_id IS NULL`, alias.AliasID, request.NewHostID, request.NewIdentityDigest, alias.OwnerRevision, alias.OwnershipGeneration).Scan(&raw, &digest) != nil {
			return deny()
		}
		var a HostAliasEvent
		if json.Unmarshal(raw, &a) != nil || hostaction.Digest(a) != digest || hostaction.Digest(a.Alias) != hostaction.Digest(alias) || a.ReplacementID != request.ReplacementID || a.Execution.RunID != ref.RunID || a.Execution.StepID != ref.StepID || a.Execution.LeaseID != ref.LeaseID || a.RecoveryEpoch != epoch {
			return deny()
		}
	}
	return &NativeReplacementRecoveryEvidence{CurrentProfileID: rolePlan.HostRoleScope.ProfileID, CurrentProfileLockDigest: rolePlan.HostRoleScope.ProfileLockDigest, Binding: b, Replacement: state, Continuity: continuity.Reference, CanaryDigest: canaryDigest, CanaryRunID: b.CanaryRunID, CanaryEventID: eventID, VerifiedAt: verifiedAt}, nil
}
