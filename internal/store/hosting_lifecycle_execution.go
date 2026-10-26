package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostinglifecycle"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"time"
)

type HostingLifecycleApply = GrantBatchApply

func (r *HostingLifecycleRepository) validateHostingLifecycleExecution(ctx context.Context, row discoveryRow, p generated.Plan, b generated.HostingLifecycleRequest, in HostingLifecycleApply, now time.Time, excluded ...string) error {
	deny := func() error { return actionError(generated.ErrorCodeAuthorizationDenied) }
	var state, epoch int64
	if row(`SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&state, &epoch) != nil || state != p.Binding.StateRevision || epoch != p.Binding.RecoveryEpoch {
		return actionError(generated.ErrorCodePlanStale)
	}
	if p.ServiceRecovery != nil || p.ServiceDeployment != nil || p.ServiceImport != nil || p.NetworkEndpoint != nil || p.AuthorizationGrantBatch != nil || p.HostAction != nil || p.HostAdoption != nil || p.HostDiscoveryTarget != nil || p.HostReplacement != nil || p.HostAliasClaim != nil || p.HostRoleScope != nil || p.HostBaselineScope != nil || p.HostAccessSequence != nil || p.ReplacementContinuity != nil || p.NativeRestart != nil || len(p.Extensions) != 0 {
		return deny()
	}
	if p.AuthorizationBranch != "human" || p.ExecutorMode != "central" || p.Risk != "control-plane" || len(p.Operations) != 1 || p.PlanID != in.PlanID || p.PlanDigest != in.PlanDigest || hostinglifecycle.Digest(p.HostingLifecycle) != hostinglifecycle.Digest(b) {
		return deny()
	}
	expires, err := time.Parse(time.RFC3339, p.ExpiresAt)
	if err != nil || !now.Before(expires) {
		return actionError(generated.ErrorCodePlanStale)
	}
	op := p.Operations[0]
	if op.OperationID != hostinglifecycle.OperationID || op.OperationType != hostinglifecycle.Operation || op.AdapterID != hostinglifecycle.AdapterID || op.TargetID != b.TargetID || op.InputDigest != hostinglifecycle.Digest(b) || op.ArtifactDigest != hostinglifecycle.Digest(b) {
		return deny()
	}
	var raw []byte
	var reason string
	var d generated.DeclarationRevision
	if row(`SELECT canonical_bytes,reason_digest FROM declaration_revisions WHERE declaration_id=? AND declaration_revision=?`, p.DeclarationID, p.Binding.DeclarationRevision).Scan(&raw, &reason) != nil || !decodeStoredDeclaration(raw, reason, &d) || !ValidateHostingLifecycleDeclaration(d) || hostinglifecycle.Digest(d.HostingLifecycle) != hostinglifecycle.Digest(b) {
		return deny()
	}
	var original generated.DeclarationRevision
	if row(`SELECT canonical_bytes,reason_digest FROM declaration_revisions WHERE declaration_id=? AND declaration_revision=?`, p.DeclarationID, 1).Scan(&raw, &reason) != nil || !decodeStoredDeclaration(raw, reason, &original) || original.Status != "draft" || !ValidateHostingLifecycleDeclaration(original) || hostinglifecycle.Digest(original.HostingLifecycle) != hostinglifecycle.Digest(b) {
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
	if _, err := adoptionPrincipalGrant(actor, row, b.TargetID, "hosting", "author", "hosting.lifecycle.prepare", true); err != nil {
		return err
	}
	if err := authorizeBaselinePrincipal(ctx, row, p, actor.ID, b.TargetID, authorization.ActionExecute, hostinglifecycle.Operation, "execution-target"); err != nil {
		return err
	}
	if err := authorizeBaselinePrincipal(ctx, row, p, human, b.TargetID, authorization.ActionAcknowledge, "plan.acknowledge", "plan-target"); err != nil {
		return err
	}
	{
		var n int
		if row(`SELECT COUNT(*) FROM effective_authorization_principals p JOIN effective_authorization_grants g ON g.principal_id=p.principal_id AND g.grant_revision=p.grant_revision WHERE p.principal_id=? AND p.principal_kind='human' AND p.status='active' AND g.status='active' AND g.role_id IN ('infrastructure-admin','control-plane-admin') AND g.action='acknowledge' AND g.branch='human' AND g.capability='plan.acknowledge' AND g.resource_kind='plan-target' AND g.resource_id=?`, human, b.TargetID).Scan(&n) != nil || n == 0 {
			return deny()
		}
	}
	return r.validate(actor, row, b)
}

func (r *HostingLifecycleRepository) ExecutionActor(ctx context.Context, in HostingLifecycleApply) (out identity.Principal, err error) {
	if r == nil || r.store == nil {
		return out, actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	p, err := NewPlanRepository(r.store).GetPlan(ctx, in.PlanID)
	if err != nil {
		return out, err
	}
	if p.Plan.HostingLifecycle == nil {
		return out, actionError(generated.ErrorCodeAuthorizationDenied)
	}
	err = r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
		if e := r.validateHostingLifecycleExecution(ctx, row, p.Plan, *p.Plan.HostingLifecycle, in, r.store.config.Clock().UTC()); e != nil {
			return e
		}
		var e error
		out, e = serviceImportActor(row, in)
		return e
	})
	return
}

// Begin commits the single mutation attempt before any provider callback. Its
// audit event does not advance desired state, preserving this exact plan lease.
func (r *HostingLifecycleRepository) Begin(ctx context.Context, in HostingLifecycleApply) error {
	p, err := NewPlanRepository(r.store).GetPlan(ctx, in.PlanID)
	if err != nil {
		return err
	}
	b := p.Plan.HostingLifecycle
	if b == nil {
		return actionError(generated.ErrorCodeAuthorizationDenied)
	}
	digest := hostinglifecycle.Digest(b)
	event := audit.EventDraft{Type: "hosting.lifecycle-attempted", CorrelationID: in.RunID, Attribution: in.Attribution, Target: audit.Target{Kind: "service", ID: b.TargetID}, After: (*audit.Fingerprint)(&digest)}
	expected := RevisionToken{StateRevision: p.Plan.Binding.StateRevision, RecoveryEpoch: p.Plan.Binding.RecoveryEpoch}
	result, err := r.store.executeAuditIntent(ctx, intentRequest{Expected: &expected, Idempotency: audit.IntentKey{Scope: "hosting-lifecycle-attempt", KeyDigest: digestParts("hosting-lifecycle-attempt", in.PlanID), RequestDigest: audit.Fingerprint(hostinglifecycle.Digest(in))}, Event: event}, false, func(ctx context.Context, tx *sql.Tx) error {
		row := func(q string, a ...any) *sql.Row { return tx.QueryRowContext(ctx, q, a...) }
		if err := r.validateHostingLifecycleExecution(ctx, row, p.Plan, *b, in, r.store.config.Clock().UTC()); err != nil {
			return err
		}
		var n int
		if row(`SELECT COUNT(*) FROM hosting_lifecycle_attempts WHERE plan_id=? OR (run_id=? AND step_id=?) OR (target_id=? AND recovery_epoch=? AND status='attempted')`, in.PlanID, in.RunID, in.StepID, b.TargetID, b.RecoveryEpoch).Scan(&n) != nil || n != 0 {
			return actionError(generated.ErrorCodeStateConflict)
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO hosting_lifecycle_attempts(plan_id,run_id,step_id,request_digest,target_id,recovery_epoch,status) VALUES(?,?,?,?,?,?,'attempted')`, in.PlanID, in.RunID, in.StepID, digest, b.TargetID, b.RecoveryEpoch)
		return err
	})
	if err != nil {
		return err
	}
	if !result.Created {
		return actionError(generated.ErrorCodeStateConflict)
	}
	return nil
}
func hostingLifecycleRecord(in generated.HostingLifecycleRequest, apply HostingLifecycleApply, out hostinglifecycle.Outcome, now time.Time) (generated.HostingLifecycleRecord, error) {
	if out.Status != "succeeded" && out.Status != "failed" && out.Status != "partial" {
		out.Status = "partial"
	}
	if out.ResultDigest == "" {
		out.ResultDigest = hostinglifecycle.Digest("no-proof")
		out.Status = "partial"
	}
	if out.OwnedResources == nil {
		out.OwnedResources = []generated.HostingOwnedResource{}
	}
	record := generated.HostingLifecycleRecord{Schema: generated.SchemaIDHostingLifecycleRecord, SchemaVersion: "1.0.0", Request: in, OwnedResources: out.OwnedResources, Revision: in.ExpectedLifecycleRevision + 1, Status: out.Status, ResultDigest: out.ResultDigest, PlanID: apply.PlanID, RunID: apply.RunID, CompletedAt: now.UTC().Truncate(time.Second).Format(time.RFC3339)}
	raw, _ := json.Marshal(record)
	if generated.ValidateContractJSON(generated.SchemaIDHostingLifecycleRecord, raw, generated.ContractExact) != nil {
		return record, actionError(generated.ErrorCodeInputInvalid)
	}
	return record, nil
}
func (r *HostingLifecycleRepository) Complete(ctx context.Context, in HostingLifecycleApply, out hostinglifecycle.Outcome) (digest string, err error) {
	p, err := NewPlanRepository(r.store).GetPlan(ctx, in.PlanID)
	if err != nil {
		return "", err
	}
	b := p.Plan.HostingLifecycle
	if b == nil {
		return "", actionError(generated.ErrorCodeAuthorizationDenied)
	}
	record, err := hostingLifecycleRecord(*b, in, out, r.store.config.Clock())
	if err != nil {
		return "", err
	}
	digest = hostinglifecycle.Digest(record)
	// If authority was revoked after provider I/O, retain a partial result instead
	// of losing the uncertain attempt. Completion never grants another mutation.
	authorityErr := r.store.Read(ctx, func(tx ReadTx) error {
		return r.validateHostingLifecycleExecution(ctx, func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }, p.Plan, *b, in, r.store.config.Clock().UTC())
	})
	if authorityErr != nil {
		record.Status = "partial"
		digest = hostinglifecycle.Digest(record)
	}
	event := audit.EventDraft{Type: "hosting.lifecycle-completed", CorrelationID: in.RunID, Attribution: in.Attribution, Target: audit.Target{Kind: "service", ID: b.TargetID}, After: (*audit.Fingerprint)(&digest)}
	_, err = r.store.executeAuditIntent(ctx, intentRequest{Idempotency: audit.IntentKey{Scope: "hosting-lifecycle-complete", KeyDigest: digestParts("hosting-lifecycle-complete", in.PlanID), RequestDigest: audit.Fingerprint(digest)}, Event: event}, true, func(ctx context.Context, tx *sql.Tx) error {
		var n int
		if tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM hosting_lifecycle_attempts WHERE plan_id=? AND run_id=? AND step_id=? AND request_digest=? AND recovery_epoch=? AND status='attempted'`, in.PlanID, in.RunID, in.StepID, hostinglifecycle.Digest(b), b.RecoveryEpoch).Scan(&n) != nil || n != 1 {
			return actionError(generated.ErrorCodeStateConflict)
		}
		// The approved actor is sealed to this attempt, even after grant revocation.
		row := func(q string, a ...any) *sql.Row { return tx.QueryRowContext(ctx, q, a...) }
		var actor string
		if row(`SELECT principal_id FROM service_import_run_actors WHERE run_id=? AND principal_id=? AND principal_method=?`, in.RunID, in.Attribution.AuthenticatedPrincipalID, in.Attribution.AuthenticatedPrincipalMethod).Scan(&actor) != nil {
			return actionError(generated.ErrorCodeAuthorizationDenied)
		}
		if record.Status == "succeeded" {
			if err := r.validateHostingLifecycleExecution(ctx, row, p.Plan, *b, in, r.store.config.Clock().UTC()); err != nil {
				return err
			}
		}
		raw, _ := json.Marshal(record)
		if _, err := tx.ExecContext(ctx, `INSERT INTO hosting_lifecycle_records(target_id,revision,plan_id,run_id,recovery_epoch,status,canonical_bytes,digest) VALUES(?,?,?,?,?,?,?,?)`, b.TargetID, record.Revision, in.PlanID, in.RunID, b.RecoveryEpoch, record.Status, raw, digest); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE hosting_lifecycle_attempts SET status=? WHERE plan_id=? AND status='attempted'`, record.Status, in.PlanID)
		return err
	})
	return
}
func (r *HostingLifecycleRepository) Verify(ctx context.Context, planID, runID, digest string) error {
	return r.store.Read(ctx, func(tx ReadTx) error {
		var raw []byte
		var stored string
		var record generated.HostingLifecycleRecord
		if tx.queryRow(ctx, `SELECT canonical_bytes,digest FROM hosting_lifecycle_records WHERE plan_id=? AND run_id=? AND status='succeeded'`, planID, runID).Scan(&raw, &stored) != nil || stored != digest || json.Unmarshal(raw, &record) != nil || hostinglifecycle.Digest(record) != digest {
			return actionError(generated.ErrorCodeIntegrityFailure)
		}
		return nil
	})
}
