package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

func (r *CredentialRepository) RecordNativeRestartPending(ctx context.Context, p credentialref.NativeRestartPending, a audit.Attribution) error {
	return NewRunRepository(r.store).RecordNativeRestartPending(ctx, p, a)
}
func (r *CredentialRepository) ReadNativeRestartPending(ctx context.Context, runID, stepID string) (credentialref.NativeRestartPending, error) {
	return NewRunRepository(r.store).ReadNativeRestartPending(ctx, runID, stepID)
}
func (r *RunRepository) RecordNativeRestartPending(ctx context.Context, p credentialref.NativeRestartPending, a audit.Attribution) error {
	raw, err := credentialref.EncodeNativeRestartPending(p)
	if err != nil {
		return credentialStoreError(generated.ErrorCodeInputInvalid, "native-restart-pending")
	}
	if r == nil || r.store == nil {
		return credentialStoreError(generated.ErrorCodePrerequisiteBlocked, "native-restart-pending")
	}
	identity := audit.Fingerprint(credentialref.NativeRestartPendingDigest(p))
	intent, err := r.store.executeAuditIntent(ctx, intentRequest{Idempotency: audit.IntentKey{Scope: "native-restart-pending", KeyDigest: identity, RequestDigest: identity}, Event: audit.EventDraft{Type: "run.native-restart-pending", CorrelationID: p.RunID, Attribution: a, Target: audit.Target{Kind: "run", ID: p.RunID}, After: &identity}}, false, func(ctx context.Context, tx *sql.Tx) error {
		var canonical []byte
		if err := tx.QueryRowContext(ctx, `SELECT canonical_bytes FROM plan_runs WHERE run_id=?`, p.RunID).Scan(&canonical); err != nil {
			return err
		}
		value, err := decodeRun(canonical)
		if err != nil {
			return err
		}
		run := &value
		step := findStep(run, p.StepID)
		if run.Status != "running" || run.PlanID != p.PlanID || run.PlanDigest != p.PlanDigest || run.RecoveryEpoch != p.Binding.RecoveryEpoch || step == nil || step.Status != "running" || step.EffectState != "intent-recorded" || step.OperationID != p.Binding.OperationID || step.OperationType != string(p.Binding.Action) || step.AdapterID != "core.credential" || step.TargetID != p.Binding.TargetID || step.InputDigest != p.Binding.CiphertextFingerprint || step.ArtifactDigest != p.Binding.CiphertextFingerprint {
			return credentialStoreError(generated.ErrorCodePrerequisiteBlocked, "native-restart-intent")
		}
		var count int
		bindingBytes, _ := json.Marshal(p.Binding)
		err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM target_execution_leases l JOIN plan_runs r ON r.run_id=l.run_id JOIN immutable_plans p ON p.plan_id=r.plan_id JOIN credential_lifecycle_bindings b ON b.declaration_id=p.declaration_id AND b.declaration_revision=p.declaration_revision-1 JOIN acknowledgement_requests a ON a.acknowledgement_id=r.acknowledgement_id JOIN system_meta m ON m.id=1 JOIN authorization_decisions d ON d.decision_id=r.authorization_decision_id JOIN effective_authorization_principals ep ON ep.principal_id=d.principal_id WHERE l.lease_id=? AND l.run_id=? AND l.step_id=? AND l.status='active' AND l.lease_kind='central' AND l.expires_at>? AND l.maximum_expires_at>=l.expires_at AND p.expires_at>? AND a.expires_at>? AND l.recovery_epoch=m.recovery_epoch AND p.recovery_epoch=m.recovery_epoch AND p.state_revision=m.state_revision AND p.plan_digest=? AND b.operation_id=? AND b.binding_bytes=? AND a.plan_id=p.plan_id AND a.plan_digest=p.plan_digest AND a.status='approved' AND a.consumed_at IS NOT NULL AND a.state_revision=p.state_revision AND a.recovery_epoch=p.recovery_epoch AND ep.status='active' AND ep.grant_revision=d.grant_revision AND d.allowed=1 AND d.action='execute' AND d.branch='human' AND d.plan_digest=p.plan_digest AND d.state_revision=p.state_revision AND d.recovery_epoch=p.recovery_epoch`, p.LeaseID, p.RunID, p.StepID, r.store.config.Clock().UTC().Format(time.RFC3339), r.store.config.Clock().UTC().Format(time.RFC3339), r.store.config.Clock().UTC().Format(time.RFC3339), p.PlanDigest, p.Binding.OperationID, bindingBytes).Scan(&count)
		if err != nil {
			return err
		}
		if count != 1 {
			return credentialStoreError(generated.ErrorCodePrerequisiteBlocked, "native-restart-lease")
		}
		var planBytes []byte
		if err := tx.QueryRowContext(ctx, `SELECT canonical_bytes FROM immutable_plans WHERE plan_id=?`, p.PlanID).Scan(&planBytes); err != nil {
			return err
		}
		var plan generated.Plan
		if json.Unmarshal(planBytes, &plan) != nil || plan.PlanID != p.PlanID || plan.PlanDigest != p.PlanDigest || plan.Binding.StateRevision != run.StateRevision || plan.Binding.RecoveryEpoch != p.Binding.RecoveryEpoch || plan.AuthorizationBranch != "human" || plan.ExecutorMode != "central" {
			return credentialStoreError(generated.ErrorCodeIntegrityFailure, "native-restart-plan")
		}
		matched := false
		for _, op := range plan.Operations {
			if op.OperationID == p.Binding.OperationID && op.OperationType == string(p.Binding.Action) && op.AdapterID == "core.credential" && op.TargetID == p.Binding.TargetID && op.InputDigest == p.Binding.CiphertextFingerprint && op.ArtifactDigest == p.Binding.CiphertextFingerprint {
				matched = true
			}
		}
		if !matched {
			return credentialStoreError(generated.ErrorCodeIntegrityFailure, "native-restart-plan-operation")
		}
		result, err := tx.ExecContext(ctx, `UPDATE plan_run_steps SET native_restart_pending_bytes=? WHERE run_id=? AND step_id=? AND active_lease_id=? AND native_restart_pending_bytes IS NULL AND native_restart_consumed_run_id IS NULL`, raw, p.RunID, p.StepID, p.LeaseID)
		if err != nil {
			return err
		}
		n, _ := result.RowsAffected()
		if n != 1 {
			return credentialStoreError(generated.ErrorCodeStateConflict, "native-restart-pending")
		}
		return nil
	})
	if err == nil && !intent.Created {
		return credentialStoreError(generated.ErrorCodeStateConflict, "native-restart-already-pending")
	}
	return err
}
func (r *RunRepository) ReadNativeRestartPending(ctx context.Context, runID, stepID string) (credentialref.NativeRestartPending, error) {
	var p credentialref.NativeRestartPending
	if r == nil || r.store == nil || !validRunToken(runID) || !validRunToken(stepID) {
		return p, credentialStoreError(generated.ErrorCodeInputInvalid, "native-restart-pending")
	}
	var raw []byte
	err := r.store.Read(ctx, func(tx ReadTx) error {
		err := tx.queryRow(ctx, `SELECT s.native_restart_pending_bytes FROM plan_run_steps s JOIN plan_runs r ON r.run_id=s.run_id JOIN system_meta m ON m.id=1 WHERE s.run_id=? AND s.step_id=? AND r.status='partial' AND s.status='partial' AND s.effect_state='effect-unknown' AND s.native_restart_pending_bytes IS NOT NULL AND s.native_restart_consumed_run_id IS NULL AND r.recovery_epoch=m.recovery_epoch`, runID, stepID).Scan(&raw)
		if err != nil {
			return err
		}
		p, err = credentialref.DecodeNativeRestartPending(raw)
		if err != nil || p.RunID != runID || p.StepID != stepID {
			return credentialStoreError(generated.ErrorCodeIntegrityFailure, "native-restart-pending")
		}
		return requireNativeRestartOrigin(p, func(q string, args ...any) *sql.Row { return tx.queryRow(ctx, q, args...) })
	})
	if err != nil {
		return p, credentialStoreError(generated.ErrorCodePrerequisiteBlocked, "native-restart-pending")
	}
	p, err = credentialref.DecodeNativeRestartPending(raw)
	if err != nil || p.RunID != runID || p.StepID != stepID {
		return credentialref.NativeRestartPending{}, credentialStoreError(generated.ErrorCodeIntegrityFailure, "native-restart-pending")
	}
	return p, nil
}
func consumeNativeRestartPending(ctx context.Context, tx *sql.Tx, request CredentialLifecycleApplyRequest) error {
	c := request.Binding.NativeRestartContinuation
	if c == nil {
		return nil
	}
	var raw []byte
	err := tx.QueryRowContext(ctx, `SELECT s.native_restart_pending_bytes FROM plan_run_steps s JOIN plan_runs r ON r.run_id=s.run_id JOIN system_meta m ON m.id=1 WHERE s.run_id=? AND s.step_id=? AND r.status='partial' AND s.status='partial' AND s.effect_state='effect-unknown' AND s.native_restart_consumed_run_id IS NULL AND r.recovery_epoch=m.recovery_epoch`, c.PriorRunID, c.PriorStepID).Scan(&raw)
	if err != nil {
		return credentialStoreError(generated.ErrorCodePrerequisiteBlocked, "native-restart-pending")
	}
	p, err := credentialref.DecodeNativeRestartPending(raw)
	if err != nil || !credentialref.PendingMatchesLifecycle(p, request.Binding) {
		return credentialStoreError(generated.ErrorCodePrerequisiteBlocked, "native-restart-pending")
	}
	if err := requireNativeRestartOrigin(p, func(q string, args ...any) *sql.Row { return tx.QueryRowContext(ctx, q, args...) }); err != nil {
		return err
	}
	found := false
	for _, v := range request.Verifications {
		if v.Result == "verified" && v.NativeReceipt != nil && v.NativeReceipt.Proof == c.Expected && v.NativeReceipt.PlanDigest == request.Stage.PlanDigest && v.NativeReceipt.RunID == request.Stage.RunID && v.NativeReceipt.StepID == request.Stage.StepID {
			found = true
		}
	}
	if !found {
		return credentialStoreError(generated.ErrorCodePrerequisiteBlocked, "native-restart-receipt")
	}
	result, err := tx.ExecContext(ctx, `UPDATE plan_run_steps SET native_restart_consumed_run_id=?,native_restart_consumed_step_id=? WHERE run_id=? AND step_id=? AND native_restart_pending_bytes=? AND native_restart_consumed_run_id IS NULL`, request.Stage.RunID, request.Stage.StepID, c.PriorRunID, c.PriorStepID, raw)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return credentialStoreError(generated.ErrorCodeStateConflict, "native-restart-consumed")
	}
	return nil
}

func requireNativeRestartOrigin(p credentialref.NativeRestartPending, row func(string, ...any) *sql.Row) error {
	var count int
	bindingBytes, _ := json.Marshal(p.Binding)
	err := row(`SELECT COUNT(*) FROM plan_runs r JOIN plan_run_steps s ON s.run_id=r.run_id JOIN immutable_plans i ON i.plan_id=r.plan_id JOIN credential_lifecycle_bindings b ON b.declaration_id=i.declaration_id AND b.declaration_revision=i.declaration_revision-1 JOIN system_meta m ON m.id=1 WHERE r.run_id=? AND s.step_id=? AND r.plan_id=? AND r.plan_digest=? AND s.operation_id=? AND s.operation_type=? AND s.adapter_id='core.credential' AND s.target_id=? AND s.artifact_digest=? AND s.active_lease_id=? AND r.recovery_epoch=? AND r.recovery_epoch=m.recovery_epoch AND b.operation_id=s.operation_id AND b.binding_bytes=?`, p.RunID, p.StepID, p.PlanID, p.PlanDigest, p.Binding.OperationID, string(p.Binding.Action), p.Binding.TargetID, p.Binding.CiphertextFingerprint, p.LeaseID, p.Binding.RecoveryEpoch, bindingBytes).Scan(&count)
	if err != nil {
		return err
	}
	if count != 1 {
		return credentialStoreError(generated.ErrorCodeIntegrityFailure, "native-restart-origin")
	}
	return nil
}
