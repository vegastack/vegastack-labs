package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"time"
)

type CIEnrollmentApply = GrantBatchApply

func (r *CIEnrollmentRepository) Apply(ctx context.Context, in CIEnrollmentApply) (string, error) {
	if r == nil || r.store == nil {
		return "", actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	p, err := NewPlanRepository(r.store).GetPlan(ctx, in.PlanID)
	if err != nil {
		return "", err
	}
	b := p.Plan.CIEnrollment
	if b == nil || validateCIEnrollmentRequest(*b) != nil {
		return "", actionError(generated.ErrorCodeInputInvalid)
	}
	if err = r.store.Read(ctx, func(tx ReadTx) error {
		return r.validateCIEnrollmentExecution(ctx, func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }, p.Plan, *b, in, r.store.config.Clock().UTC(), r.store.config.NetworkConnectExcludedHostIDs...)
	}); err != nil {
		return "", err
	}
	preimage, before, err := r.store.prepareMutationSnapshot(ctx, p.Plan, in)
	if err != nil {
		return "", err
	}
	digest := ciEnrollmentDigest(b)
	event := audit.EventDraft{Type: "ci.enrollment.register-applied", CorrelationID: in.RunID, Attribution: in.Attribution, Target: audit.Target{Kind: "ci-enrollment", ID: b.Definition.EnrollmentID}, Before: (*audit.Fingerprint)(&before), After: (*audit.Fingerprint)(&digest)}
	expected := RevisionToken{StateRevision: p.Plan.Binding.StateRevision, RecoveryEpoch: p.Plan.Binding.RecoveryEpoch}
	_, err = r.store.writeIntent(ctx, intentRequest{Expected: &expected, Idempotency: audit.IntentKey{Scope: "ci-enrollment", KeyDigest: digestParts("ci-enrollment", in.RunID, in.StepID, in.LeaseID), RequestDigest: audit.Fingerprint(ciEnrollmentDigest(in))}, Event: event}, func(ctx context.Context, tx *sql.Tx) error {
		row := func(q string, a ...any) *sql.Row { return tx.QueryRowContext(ctx, q, a...) }
		if err := r.validateCIEnrollmentExecution(ctx, row, p.Plan, *b, in, r.store.config.Clock().UTC(), r.store.config.NetworkConnectExcludedHostIDs...); err != nil {
			return err
		}
		if err := r.store.verifyMutationPreimage(ctx, preimage, before); err != nil {
			return err
		}
		policy, err := r.policy(b.Definition)
		if err != nil {
			return err
		}
		record := generated.CiEnrollmentRecord{Schema: generated.SchemaIDCiEnrollmentRecord, SchemaVersion: "1.0.0", Definition: b.Definition, Revision: 1, RegistrationStatus: "registered", AdmissionStatus: "not-qualified", RegisteredAt: r.store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339), StateRevision: p.Plan.Binding.StateRevision + 1, RecoveryEpoch: b.RecoveryEpoch}
		raw, _ := json.Marshal(record)
		_, err = tx.ExecContext(ctx, `INSERT INTO ci_enrollments(enrollment_id,resource_key_digest,canonical_bytes,digest,import_digest,plan_id,run_id,binding_bytes,binding_digest) VALUES(?,?,?,?,?,?,?,?,?)`, b.Definition.EnrollmentID, policy.ResourceKeyDigest, raw, ciEnrollmentDigest(record), digest, in.PlanID, in.RunID, mustCIEnrollmentBytes(policy.Binding), policy.Definition.BindingDigest)
		return err
	})
	return digest, err
}
func (r *CIEnrollmentRepository) Verify(ctx context.Context, planID, runID, digest string) error {
	if r == nil || r.store == nil {
		return actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	stored, err := NewPlanRepository(r.store).GetPlan(ctx, planID)
	if err != nil {
		return err
	}
	request := stored.Plan.CIEnrollment
	if request == nil || ciEnrollmentDigest(request) != digest {
		return actionError(generated.ErrorCodeIntegrityFailure)
	}
	return r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
		var n int
		if row(`SELECT COUNT(*) FROM ci_enrollments e JOIN audit_events a ON a.correlation_id=e.run_id AND a.event_type='ci.enrollment.register-applied' WHERE e.plan_id=? AND e.run_id=? AND e.import_digest=? AND a.after_fingerprint=e.import_digest`, planID, runID, digest).Scan(&n) != nil || n != 1 {
			return actionError(generated.ErrorCodeIntegrityFailure)
		}
		record, err := readCIEnrollment(row, request.Definition.EnrollmentID)
		if err != nil {
			return err
		}
		if record.Definition != request.Definition || record.Revision != 1 || record.RecoveryEpoch != request.RecoveryEpoch || record.StateRevision != stored.Plan.Binding.StateRevision+1 {
			return actionError(generated.ErrorCodeIntegrityFailure)
		}
		return nil
	})
}
func (r *CIEnrollmentRepository) validateCIEnrollmentExecution(ctx context.Context, row discoveryRow, p generated.Plan, b generated.CiEnrollmentRequest, in CIEnrollmentApply, now time.Time, excluded ...string) error {
	deny := func() error { return actionError(generated.ErrorCodeAuthorizationDenied) }
	var state, epoch int64
	if row(`SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&state, &epoch) != nil || state != p.Binding.StateRevision || epoch != p.Binding.RecoveryEpoch {
		return actionError(generated.ErrorCodePlanStale)
	}
	if p.AuthorizationBranch != "human" || p.ExecutorMode != "central" || p.Risk != "control-plane" || len(p.Operations) != 1 || p.PlanID != in.PlanID || p.PlanDigest != in.PlanDigest || ciEnrollmentDigest(p.CIEnrollment) != ciEnrollmentDigest(b) {
		return deny()
	}
	expires, err := time.Parse(time.RFC3339, p.ExpiresAt)
	if err != nil || !now.Before(expires) {
		return actionError(generated.ErrorCodePlanStale)
	}
	op := p.Operations[0]
	if op.OperationID != "ci-enrollment" || op.OperationType != ciEnrollmentOperation || op.AdapterID != ciEnrollmentAdapterID || op.TargetID != b.Definition.EnrollmentID || op.InputDigest != ciEnrollmentDigest(b) || op.ArtifactDigest != ciEnrollmentDigest(b) {
		return deny()
	}
	var raw []byte
	var reason string
	var d generated.DeclarationRevision
	if row(`SELECT canonical_bytes,reason_digest FROM declaration_revisions WHERE declaration_id=? AND declaration_revision=?`, p.DeclarationID, p.Binding.DeclarationRevision).Scan(&raw, &reason) != nil || !decodeStoredDeclaration(raw, reason, &d) || !ValidateCIEnrollmentDeclaration(d) || ciEnrollmentDigest(d.CIEnrollment) != ciEnrollmentDigest(b) {
		return deny()
	}
	var original generated.DeclarationRevision
	if row(`SELECT canonical_bytes,reason_digest FROM declaration_revisions WHERE declaration_id=? AND declaration_revision=?`, p.DeclarationID, b.ExpectedDeclarationRevision+1).Scan(&raw, &reason) != nil || !decodeStoredDeclaration(raw, reason, &original) || original.Status != "draft" || !ValidateCIEnrollmentDeclaration(original) || ciEnrollmentDigest(original.CIEnrollment) != ciEnrollmentDigest(b) {
		return deny()
	}
	var human string

	if row(`SELECT a.human_id FROM plan_runs r JOIN acknowledgement_requests a ON a.acknowledgement_id=r.acknowledgement_id JOIN plan_run_steps s ON s.run_id=r.run_id JOIN target_execution_leases l ON l.lease_id=s.active_lease_id WHERE r.run_id=? AND r.plan_id=? AND r.plan_digest=? AND r.status='running' AND r.cancellation_requested=0 AND r.executor_mode='central' AND a.plan_id=r.plan_id AND a.plan_digest=r.plan_digest AND a.status='approved' AND a.consumed_at IS NOT NULL AND a.recovery_epoch=r.recovery_epoch AND s.step_id=? AND s.operation_id=? AND s.operation_type=? AND s.adapter_id=? AND s.target_id=? AND s.input_digest=? AND s.artifact_digest=? AND s.status='running' AND s.effect_state='intent-recorded' AND l.lease_id=? AND l.status='active' AND l.run_id=r.run_id AND l.step_id=s.step_id AND l.target_id=s.target_id AND l.recovery_epoch=r.recovery_epoch AND l.recovery_epoch=? AND l.expires_at>?`, in.RunID, in.PlanID, in.PlanDigest, in.StepID, op.OperationID, op.OperationType, op.AdapterID, op.TargetID, op.InputDigest, op.ArtifactDigest, in.LeaseID, p.Binding.RecoveryEpoch, now.Format(time.RFC3339)).Scan(&human) != nil {
		return actionError(generated.ErrorCodeApprovalRequired)
	}
	if in.Attribution.ResponsibleHumanPrincipalID == nil || *in.Attribution.ResponsibleHumanPrincipalID != human {
		return deny()
	}
	actor, err := serviceImportActor(row, in)
	if err != nil {
		return err
	}
	if _, err := adoptionPrincipalGrant(actor, row, b.Definition.EnrollmentID, "ci-enrollment", "author", "ci.enrollment.prepare", false); err != nil {
		return err
	}
	if _, err := adoptionPrincipalGrant(actor, row, b.Definition.EnrollmentID, "execution-target", "execute", ciEnrollmentOperation, true); err != nil {
		return err
	}
	var count int
	if row(`SELECT COUNT(*) FROM effective_authorization_principals p JOIN effective_authorization_grants g ON g.principal_id=p.principal_id AND g.grant_revision=p.grant_revision WHERE p.principal_id=? AND p.principal_kind='human' AND p.status='active' AND g.status='active' AND g.role_id IN ('control-plane-admin','infrastructure-admin') AND g.action='acknowledge' AND g.branch='human' AND g.capability='plan.acknowledge' AND g.resource_kind='plan-target' AND g.resource_id=?`, human, b.Definition.EnrollmentID).Scan(&count) != nil || count == 0 {
		return deny()
	}
	return r.validate(actor, row, b)
}

func mustCIEnrollmentBytes(v any) []byte { b, _ := json.Marshal(v); return b }
