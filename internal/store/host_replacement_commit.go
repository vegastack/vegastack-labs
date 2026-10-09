package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostreplacement"
	"github.com/vegastack/vegastack-labs/internal/linuxrole"
)

type HostReplacementCommit struct {
	Execution HostReplacementExecution
	Admission HostAdmissionSnapshot
}

func verifiedReplacementRestore(row discoveryRow, q generated.HostReplacementRequest, epoch int64) (generated.RestoreBinding, error) {
	var b generated.RestoreBinding
	var raw []byte
	if q.Source == nil {
		return b, replacementError(generated.ErrorCodePrerequisiteBlocked)
	}
	err := row(`SELECT b.binding_bytes FROM recovery_authority_bundles b JOIN recovery_authority_journal j ON j.plan_id=b.plan_id AND j.plan_digest=b.plan_digest AND j.transition='verified' WHERE json_extract(b.binding_bytes,'$.replacementContinuity.replacementId')=? AND json_extract(b.binding_bytes,'$.source.pointId')=?`, q.ReplacementID, q.Source.PointID).Scan(&raw)
	if err != nil || json.Unmarshal(raw, &b) != nil || hostreplacement.BindRestore(q, b) != nil || b.NextRecoveryEpoch != epoch {
		return b, replacementError(generated.ErrorCodePrerequisiteBlocked)
	}
	return b, nil
}
func (r *HostReplacementRepository) Commit(ctx context.Context, q HostReplacementCommit) (out generated.HostReplacementState, err error) {
	x := q.Execution
	intent := discoveryIntent(x.Attribution, "host.replacement.committed", x.ReplacementID, hostaction.Digest(x), hostaction.Digest(struct {
		Execution HostReplacementExecution
		Snapshot  string
	}{x, HostAdmissionSnapshotDigest(q.Admission)}))
	_, err = r.store.executeAuditIntent(ctx, intent, false, func(ctx context.Context, tx *sql.Tx) error {
		row := func(q string, a ...any) *sql.Row { return tx.QueryRowContext(ctx, q, a...) }
		p, e := r.execution(ctx, row, x, hostreplacement.CommitOperation)
		if e != nil {
			return e
		}
		d, e := readReplacementDraft(row, x.DraftID)
		if e != nil {
			return e
		}
		if d.Request.Operation != "commit" || d.Request.ReplacementID != x.ReplacementID || p.HostReplacement == nil || hostaction.Digest(*p.HostReplacement) != d.Digest || p.Operations[0].InputDigest != d.Digest || p.Operations[0].ArtifactDigest != d.Digest {
			return replacementError(generated.ErrorCodeIntegrityFailure)
		}
		if e = validateReplacementHosts(row, d.Request); e != nil {
			return e
		}
		if e = r.validateReplacementOwnedScope(ctx, ReadTx{handle: tx}, d.Request); e != nil {
			return e
		}
		event, _, e := readReplacementEvent(row, x.ReplacementID)
		if e != nil {
			return e
		}
		if event.Type != "fence-observed" || event.State.BindingDigest != d.BindingDigest || event.Execution.RunID != x.RunID || event.Execution.StepID != x.StepID || event.Execution.LeaseID != x.LeaseID {
			return replacementError(generated.ErrorCodePrerequisiteBlocked)
		}
		var scope HostReplacementFenceScope
		if e = r.replacementFenceScope(ctx, ReadTx{handle: tx}, x, &scope); e != nil {
			return e
		}
		var fence HostReplacementFenceReceipt
		if json.Unmarshal(event.FenceReceipt, &fence) != nil || event.AuthorityDigest != scope.AuthorityDigest || validateFenceBinding(fence.Binding, x, scope, r.store.config.Clock()) != nil || !r.store.config.Clock().Before(fence.ExpiresAt) {
			return replacementError(generated.ErrorCodePlanStale)
		}
		if q.Admission.Host.HostID != d.Request.NewHostID || q.Admission.IdentityDigest != d.Request.NewIdentityDigest || q.Admission.RoleBindingDigest != d.Request.ProposedRoleBindingDigest || q.Admission.ProfileLockDigest != d.Request.ProfileLockDigest || q.Admission.RoleIntentRevision <= 0 {
			return replacementError(generated.ErrorCodePrerequisiteBlocked)
		}
		if e = validateReplacementRoleIntent(row, d.Request, q.Admission.RoleIntentRevision); e != nil {
			return e
		}
		bound, e := hostRunReadContext(ctx, row, x.RunID)
		if e != nil {
			return e
		}
		if e = r.gates.validateHostAdmissionSnapshot(bound, ReadTx{handle: tx}, q.Admission); e != nil {
			return e
		}
		var originalID string
		if e = row(`SELECT draft_id FROM host_replacement_drafts WHERE replacement_id=? AND operation='freeze'`, x.ReplacementID).Scan(&originalID); e != nil {
			return e
		}
		original, e := readReplacementDraft(row, originalID)
		if e != nil {
			return e
		}
		out = event.State
		if d.Request.RestorationClass == "control-database" {
			restore, e := verifiedReplacementRestore(row, original.Request, p.Binding.RecoveryEpoch)
			if e != nil {
				return e
			}
			out.RestorePlanID = &restore.PlanID
			out.RestorationReceiptDigest = hostaction.Digest(restore)
			out.ContinuityDigest = restore.ReplacementContinuity.Digest
		} else if d.Request.Source != nil || len(d.Request.PayloadIDs) != 0 {
			return replacementError(generated.ErrorCodePrerequisiteBlocked)
		}
		if e = commitReplacementAliases(ctx, tx, x, d.Request, p, &out); e != nil {
			return e
		}
		out.Status = "committed"
		out.NextAction = "none"
		out.Blockers = []string{}
		out.PlanID = &x.PlanID
		out.RunID = &x.RunID
		out.DeclarationID = d.ID
		out.DeclarationRevision = p.Binding.DeclarationRevision
		out.StateRevision = p.Binding.StateRevision
		out.RecoveryEpoch = p.Binding.RecoveryEpoch
		out.RoleIntentRevision = q.Admission.RoleIntentRevision
		out.AdmissionSnapshotDigest = HostAdmissionSnapshotDigest(q.Admission)
		event.Sequence++
		event.Type = "committed"
		event.Execution = x
		event.State = out
		event.At = replacementNow(r.store)
		_, e = insertReplacementEvent(ctx, tx, event)
		return e
	})
	if err != nil {
		return out, err
	}
	if out.ReplacementID == "" {
		return r.Get(ctx, x.ReplacementID)
	}
	return
}

func commitReplacementAliases(ctx context.Context, tx *sql.Tx, x HostReplacementExecution, request generated.HostReplacementRequest, p generated.Plan, out *generated.HostReplacementState) error {
	row := func(q string, a ...any) *sql.Row { return tx.QueryRowContext(ctx, q, a...) }
	var e error
	for i, alias := range request.AliasBindings {
		if e = validateAliasOwner(row, alias, true, x.ReplacementID); e != nil {
			return e
		}
		var previous string
		if e = row(`SELECT event_digest FROM host_alias_owners WHERE alias_id=?`, alias.AliasID).Scan(&previous); e != nil {
			return e
		}
		alias.OwnerRevision += 2
		alias.OwnerHostID = request.NewHostID
		alias.OwnerIdentityDigest = request.NewIdentityDigest
		alias.OwnershipGeneration = out.ProposedOwnershipGeneration
		if e = insertAliasEvent(ctx, tx, HostAliasEvent{Alias: alias, PreviousDigest: previous, ReplacementID: x.ReplacementID, Execution: x, StateRevision: p.Binding.StateRevision, RecoveryEpoch: p.Binding.RecoveryEpoch}); e != nil {
			return e
		}
		result, e := tx.ExecContext(ctx, `UPDATE host_alias_owners SET owner_host_id=?,owner_identity_digest=?,owner_revision=?,ownership_generation=?,event_digest=(SELECT event_digest FROM host_alias_history WHERE alias_id=? AND owner_revision=?),frozen_replacement_id=NULL WHERE alias_id=? AND owner_revision=? AND owner_host_id=? AND owner_identity_digest=? AND frozen_replacement_id=?`, alias.OwnerHostID, alias.OwnerIdentityDigest, alias.OwnerRevision, alias.OwnershipGeneration, alias.AliasID, alias.OwnerRevision, alias.AliasID, alias.OwnerRevision-1, request.OldHostID, request.OldIdentityDigest, x.ReplacementID)
		if e != nil {
			return e
		}
		n, _ := result.RowsAffected()
		if n != 1 {
			return replacementError(generated.ErrorCodeStateConflict)
		}
		out.AliasBindings[i] = alias
	}
	return nil
}

// Collection can refresh observations but cannot substitute another declaration's
// mutation intent, even when its desired role digest happens to be identical.
func validateReplacementRoleIntent(row discoveryRow, q generated.HostReplacementRequest, intentRevision int64) error {
	var raw []byte
	var p generated.Plan
	if row(`SELECT p.canonical_bytes FROM immutable_plans p JOIN plan_runs r ON r.plan_id=p.plan_id AND r.plan_digest=p.plan_digest JOIN plan_run_steps s ON s.run_id=r.run_id WHERE s.target_id=? AND s.effect_state IN ('intent-recorded','receipt-recorded','effect-unknown','verified') AND json_extract(p.canonical_bytes,'$.hostAction.actionId') IN ('debian.role.apply','debian.control.handoff') ORDER BY p.state_revision DESC,p.plan_id DESC LIMIT 1`, q.NewHostID).Scan(&raw) != nil || json.Unmarshal(raw, &p) != nil {
		return replacementError(generated.ErrorCodePrerequisiteBlocked)
	}
	var declaration generated.DeclarationRevision
	var reason string
	if row(`SELECT canonical_bytes,reason_digest FROM declaration_revisions WHERE declaration_id=? AND declaration_revision=?`, q.ProposedRoleDeclarationID, q.ProposedRoleDeclarationRevision).Scan(&raw, &reason) != nil || !decodeStoredDeclaration(raw, reason, &declaration) {
		return replacementError(generated.ErrorCodePlanStale)
	}
	return validateReplacementRoleIntentPlan(p, declaration, q, intentRevision)
}

func validateReplacementRoleIntentPlan(p generated.Plan, declaration generated.DeclarationRevision, q generated.HostReplacementRequest, intentRevision int64) error {
	revision := declaration.Revision
	if declaration.Status == "draft" {
		revision++
	}
	if p.DeclarationID != q.ProposedRoleDeclarationID || p.Binding.DeclarationRevision != revision || p.Binding.StateRevision != intentRevision || p.HostAction == nil || p.HostRoleScope == nil || p.HostRoleScope.SubjectHostID != q.NewHostID || p.HostRoleScope.SubjectIdentityDigest != q.NewIdentityDigest || p.HostRoleScope.RoleBindingDigest != q.ProposedRoleBindingDigest || p.HostRoleScope.ProfileLockDigest != q.ProfileLockDigest {
		return replacementError(generated.ErrorCodePlanStale)
	}
	in, err := linuxrole.DecodeInput([]byte(p.HostAction.ActionInput))
	if err != nil || hostreplacement.RolePreimageDigest(in) != q.PreservedPreimageDigest {
		return replacementError(generated.ErrorCodePlanStale)
	}
	return nil
}
