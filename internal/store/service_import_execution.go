package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/servicecatalog"
	"time"
)

type ServiceImportApply = GrantBatchApply

func (r *ServiceRepository) Apply(ctx context.Context, in ServiceImportApply) (string, error) {
	if r == nil || r.store == nil {
		return "", actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	p, err := NewPlanRepository(r.store).GetPlan(ctx, in.PlanID)
	if err != nil {
		return "", err
	}
	b := p.Plan.ServiceImport
	if b == nil || servicecatalog.ValidateImportRequest(*b) != nil {
		return "", actionError(generated.ErrorCodeInputInvalid)
	}
	if err = r.store.Read(ctx, func(tx ReadTx) error {
		return r.validateServiceImportExecution(ctx, func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }, p.Plan, *b, in, r.store.config.Clock().UTC(), r.store.config.NetworkConnectExcludedHostIDs...)
	}); err != nil {
		return "", err
	}
	preimage, before, err := r.store.prepareMutationSnapshot(ctx, p.Plan, in)
	if err != nil {
		return "", err
	}
	digest := servicecatalog.Digest(b)
	event := audit.EventDraft{Type: "service.import-applied", CorrelationID: in.RunID, Attribution: in.Attribution, Target: audit.Target{Kind: "service", ID: b.Definition.ServiceID}, Before: (*audit.Fingerprint)(&before), After: (*audit.Fingerprint)(&digest)}
	expected := RevisionToken{StateRevision: p.Plan.Binding.StateRevision, RecoveryEpoch: p.Plan.Binding.RecoveryEpoch}
	_, err = r.store.writeIntent(ctx, intentRequest{Expected: &expected, Idempotency: audit.IntentKey{Scope: "service-import", KeyDigest: digestParts("service-import", in.RunID, in.StepID, in.LeaseID), RequestDigest: audit.Fingerprint(servicecatalog.Digest(in))}, Event: event}, func(ctx context.Context, tx *sql.Tx) error {
		row := func(q string, a ...any) *sql.Row { return tx.QueryRowContext(ctx, q, a...) }
		if err := r.validateServiceImportExecution(ctx, row, p.Plan, *b, in, r.store.config.Clock().UTC(), r.store.config.NetworkConnectExcludedHostIDs...); err != nil {
			return err
		}
		if err := r.store.verifyMutationPreimage(ctx, preimage, before); err != nil {
			return err
		}
		policy, err := r.policy(b.Definition)
		if err != nil {
			return err
		}
		record := generated.ServiceRecord{Schema: generated.SchemaIDServiceRecord, SchemaVersion: "1.0.0", Definition: b.Definition, Revision: 1, RegistrationStatus: "registered", HostAdmission: "not-verified", RegisteredAt: r.store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339), StateRevision: p.Plan.Binding.StateRevision + 1, RecoveryEpoch: b.RecoveryEpoch}
		raw, _ := json.Marshal(record)
		_, err = tx.ExecContext(ctx, `INSERT INTO service_catalog(service_id,resource_key_digest,canonical_bytes,digest,import_digest,plan_id,run_id) VALUES(?,?,?,?,?,?,?)`, b.Definition.ServiceID, policy.ResourceKeyDigest, raw, servicecatalog.Digest(record), digest, in.PlanID, in.RunID)
		return err
	})
	return digest, err
}
func (r *ServiceRepository) Verify(ctx context.Context, planID, runID, digest string) error {
	if r == nil || r.store == nil {
		return actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	stored, err := NewPlanRepository(r.store).GetPlan(ctx, planID)
	if err != nil {
		return err
	}
	request := stored.Plan.ServiceImport
	if request == nil || servicecatalog.Digest(request) != digest {
		return actionError(generated.ErrorCodeIntegrityFailure)
	}
	return r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
		var n int
		if row(`SELECT COUNT(*) FROM service_catalog e JOIN audit_events a ON a.correlation_id=e.run_id AND a.event_type='service.import-applied' WHERE e.plan_id=? AND e.run_id=? AND e.import_digest=? AND a.after_fingerprint=e.import_digest`, planID, runID, digest).Scan(&n) != nil || n != 1 {
			return actionError(generated.ErrorCodeIntegrityFailure)
		}
		record, err := readService(row, request.Definition.ServiceID)
		if err != nil {
			return err
		}
		if record.Definition != request.Definition || record.Revision != 1 || record.RecoveryEpoch != request.RecoveryEpoch || record.StateRevision != stored.Plan.Binding.StateRevision+1 {
			return actionError(generated.ErrorCodeIntegrityFailure)
		}
		return nil
	})
}
func (r *ServiceRepository) validateServiceImportExecution(ctx context.Context, row discoveryRow, p generated.Plan, b generated.ServiceImportRequest, in ServiceImportApply, now time.Time, excluded ...string) error {
	deny := func() error { return actionError(generated.ErrorCodeAuthorizationDenied) }
	var state, epoch int64
	if row(`SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&state, &epoch) != nil || state != p.Binding.StateRevision || epoch != p.Binding.RecoveryEpoch {
		return actionError(generated.ErrorCodePlanStale)
	}
	if p.AuthorizationBranch != "human" || p.ExecutorMode != "central" || p.Risk != "control-plane" || len(p.Operations) != 1 || p.PlanID != in.PlanID || p.PlanDigest != in.PlanDigest || servicecatalog.Digest(p.ServiceImport) != servicecatalog.Digest(b) {
		return deny()
	}
	expires, err := time.Parse(time.RFC3339, p.ExpiresAt)
	if err != nil || !now.Before(expires) {
		return actionError(generated.ErrorCodePlanStale)
	}
	op := p.Operations[0]
	if op.OperationID != "service-import" || op.OperationType != servicecatalog.Operation || op.AdapterID != servicecatalog.AdapterID || op.TargetID != b.Definition.ServiceID || op.InputDigest != servicecatalog.Digest(b) || op.ArtifactDigest != servicecatalog.Digest(b) {
		return deny()
	}
	var raw []byte
	var reason string
	var d generated.DeclarationRevision
	if row(`SELECT canonical_bytes,reason_digest FROM declaration_revisions WHERE declaration_id=? AND declaration_revision=?`, p.DeclarationID, p.Binding.DeclarationRevision).Scan(&raw, &reason) != nil || !decodeStoredDeclaration(raw, reason, &d) || !ValidateServiceImportDeclaration(d) || servicecatalog.Digest(d.ServiceImport) != servicecatalog.Digest(b) {
		return deny()
	}
	var original generated.DeclarationRevision
	if row(`SELECT canonical_bytes,reason_digest FROM declaration_revisions WHERE declaration_id=? AND declaration_revision=?`, p.DeclarationID, b.ExpectedDeclarationRevision+1).Scan(&raw, &reason) != nil || !decodeStoredDeclaration(raw, reason, &original) || original.Status != "draft" || !ValidateServiceImportDeclaration(original) || servicecatalog.Digest(original.ServiceImport) != servicecatalog.Digest(b) {
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
	if _, err := adoptionPrincipalGrant(actor, row, b.Definition.ServiceID, "service", "author", "service.import.prepare", false); err != nil {
		return err
	}
	if _, err := adoptionPrincipalGrant(actor, row, b.Definition.ServiceID, "execution-target", "execute", servicecatalog.Operation, true); err != nil {
		return err
	}
	var count int
	if row(`SELECT COUNT(*) FROM effective_authorization_principals p JOIN effective_authorization_grants g ON g.principal_id=p.principal_id AND g.grant_revision=p.grant_revision WHERE p.principal_id=? AND p.principal_kind='human' AND p.status='active' AND g.status='active' AND g.role_id IN ('control-plane-admin','infrastructure-admin') AND g.action='acknowledge' AND g.branch='human' AND g.capability='plan.acknowledge' AND g.resource_kind='plan-target' AND g.resource_id=?`, human, b.Definition.ServiceID).Scan(&count) != nil || count == 0 {
		return deny()
	}
	return r.validate(actor, row, b)
}

// ExecutionActor returns only the stored creator of this exact approved active
// effect, after rechecking its current authority. Only the server may stamp an
// authenticated context for its protected provider observation callback.
func (r *ServiceRepository) ExecutionActor(ctx context.Context, in GrantBatchApply) (out identity.Principal, err error) {
	if r == nil || r.store == nil {
		return out, actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	p, err := NewPlanRepository(r.store).GetPlan(ctx, in.PlanID)
	if err != nil {
		return out, err
	}
	if p.Plan.ServiceImport == nil {
		return out, actionError(generated.ErrorCodeAuthorizationDenied)
	}
	err = r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
		if e := r.validateServiceImportExecution(ctx, row, p.Plan, *p.Plan.ServiceImport, in, r.store.config.Clock().UTC()); e != nil {
			return e
		}
		var e error
		out, e = serviceImportActor(row, in)
		return e
	})
	if err != nil {
		out = identity.Principal{}
	}
	return
}
func serviceImportActor(row discoveryRow, in GrantBatchApply) (out identity.Principal, err error) {
	var kind string
	if row(`SELECT p.principal_kind,s.device_id FROM service_import_run_actors s JOIN effective_authorization_principals p ON p.principal_id=s.principal_id JOIN audit_events a ON a.principal_id=p.principal_id WHERE s.run_id=? AND s.principal_id=? AND s.principal_method=? AND p.status='active' AND a.event_type='run.created' AND a.correlation_id=s.run_id AND a.principal_method=s.principal_method`, in.RunID, in.Attribution.AuthenticatedPrincipalID, in.Attribution.AuthenticatedPrincipalMethod).Scan(&kind, &out.DeviceID) != nil {
		return out, actionError(generated.ErrorCodeAuthorizationDenied)
	}
	out.ID = in.Attribution.AuthenticatedPrincipalID
	out.Method = in.Attribution.AuthenticatedPrincipalMethod
	out.Kind = identity.PrincipalKind(kind)
	if !identity.ValidPrincipal(out) || (out.Kind == identity.PrincipalAgent && in.Attribution.Agent == nil) {
		return identity.Principal{}, actionError(generated.ErrorCodeAuthorizationDenied)
	}
	return out, nil
}
func persistServiceImportActor(ctx context.Context, tx *sql.Tx, run generated.Run) error {
	var raw []byte
	var p generated.Plan
	if err := tx.QueryRowContext(ctx, `SELECT canonical_bytes FROM immutable_plans WHERE plan_id=? AND plan_digest=?`, run.PlanID, run.PlanDigest).Scan(&raw); err != nil {
		return err
	}
	if json.Unmarshal(raw, &p) != nil {
		return actionError(generated.ErrorCodeIntegrityFailure)
	}
	if !IsCIPublication(p) && p.CIJob == nil && p.CIEnrollment == nil && p.HostingLifecycle == nil && p.ServiceRecovery == nil && p.ServiceImport == nil && p.ServiceDeployment == nil {
		return nil
	}
	actor, err := serviceActor(ctx)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO service_import_run_actors(run_id,principal_id,principal_method,device_id) VALUES(?,?,?,?)`, run.RunID, actor.ID, actor.Method, actor.DeviceID)
	return err
}
