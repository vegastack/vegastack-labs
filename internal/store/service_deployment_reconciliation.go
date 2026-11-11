package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/servicecatalog"
)

// DeploymentRecoveryAttempt seals an already attempted provider operation. It
// conveys no authority to replay it or to rewrite its historical run.
type DeploymentRecoveryAttempt struct {
	Request               generated.ServiceDeploymentRequest
	StartedAt, FinishedAt time.Time
	PlanDigest            string
}

func (r *DeploymentRepository) RecoveryAttempt(ctx context.Context, q generated.ServiceDeploymentRequest) (out DeploymentRecoveryAttempt, err error) {
	if servicecatalog.ValidateDeploymentRequest(q) != nil || q.Action != "reconcile" {
		return out, actionError(generated.ErrorCodeInputInvalid)
	}
	if r == nil || r.store == nil {
		return out, actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	actor, e := serviceActor(ctx)
	if e != nil {
		return out, e
	}
	err = r.store.Read(ctx, func(tx ReadTx) error {
		row := func(s string, a ...any) *sql.Row { return tx.queryRow(ctx, s, a...) }
		if e := r.validate(actor, row, q); e != nil {
			return e
		}
		var e error
		out, e = r.validateRecovery(func(s string, a ...any) *sql.Row { return tx.queryRow(ctx, s, a...) }, q)
		return e
	})
	return
}

func (r *DeploymentRepository) validateRecovery(row discoveryRow, q generated.ServiceDeploymentRequest) (out DeploymentRecoveryAttempt, err error) {
	deny := func() (DeploymentRecoveryAttempt, error) {
		return out, actionError(generated.ErrorCodeIntegrityFailure)
	}
	if q.Action != "reconcile" || q.Recovery == nil {
		return deny()
	}
	s := q.Recovery
	var raw []byte
	var readable, runDigest, started, finished, attemptStatus, effectState string
	// Only the explicitly selected incomplete attempt is eligible. A completed
	// deployment record, live lease, other target, or ordinary failed run is not.
	if row(`SELECT p.canonical_bytes,p.readable_plan,r.plan_digest,s.started_at,s.finished_at,a.status,s.effect_state
 FROM service_deployment_attempts a JOIN immutable_plans p ON p.plan_id=a.plan_id
 JOIN plan_runs r ON r.run_id=a.run_id JOIN plan_run_steps s ON s.run_id=r.run_id AND s.step_id=a.step_id
 WHERE a.plan_id=? AND a.run_id=? AND a.step_id=? AND a.request_digest=? AND a.service_id=? AND a.recovery_epoch=? AND a.status IN ('attempted','partial')
 AND r.plan_id=a.plan_id AND r.status='partial' AND r.executor_mode='central' AND r.recovery_epoch=a.recovery_epoch
 AND s.operation_id='service-deployment' AND s.operation_type=? AND s.adapter_id=? AND s.target_id=a.service_id AND s.input_digest=a.request_digest AND s.artifact_digest=a.request_digest AND s.status='partial' AND s.effect_state IN ('effect-unknown','verified')
 AND NOT EXISTS(SELECT 1 FROM target_execution_leases l WHERE l.run_id=a.run_id AND l.status='active')`, s.PriorPlanID, s.PriorRunID, s.PriorStepID, s.PriorRequestDigest, q.Definition.ServiceID, q.RecoveryEpoch, servicecatalog.DeploymentOperation, servicecatalog.DeploymentAdapterID).Scan(&raw, &readable, &runDigest, &started, &finished, &attemptStatus, &effectState) != nil {
		return deny()
	}
	var p generated.Plan
	if !decodeStoredPlan(raw, readable, &p) || p.PlanID != s.PriorPlanID || p.PlanDigest != runDigest || p.ServiceDeployment == nil || p.AuthorizationBranch != "human" || p.ExecutorMode != "central" || p.Binding.RecoveryEpoch != q.RecoveryEpoch || p.Risk != "production-like" || len(p.Operations) != 1 {
		return deny()
	}
	op := p.Operations[0]
	if op.OperationID != servicecatalog.DeploymentOperationID || op.OperationType != servicecatalog.DeploymentOperation || op.AdapterID != servicecatalog.DeploymentAdapterID || op.TargetID != q.Definition.ServiceID || op.InputDigest != s.PriorRequestDigest || op.ArtifactDigest != s.PriorRequestDigest || op.Idempotent {
		return deny()
	}
	old := *p.ServiceDeployment
	if old.Action == "reconcile" || old.Recovery != nil || servicecatalog.ValidateDeploymentRequest(old) != nil || servicecatalog.Digest(old) != s.PriorRequestDigest {
		return deny()
	}
	// Exact current policy, artifact, environment and revision; only the new
	// action, acknowledgement/state, reason and explicit selector may differ.
	if old.Definition != q.Definition || old.Binding != q.Binding || old.Artifact != q.Artifact || old.ArtifactProofDigest != q.ArtifactProofDigest || old.RecoveryEpoch != q.RecoveryEpoch || old.ExpectedDeploymentRevision > q.ExpectedDeploymentRevision || servicecatalog.Digest(old.Configuration) != servicecatalog.Digest(q.Configuration) || servicecatalog.Digest(old.EnvironmentBindings) != servicecatalog.Digest(q.EnvironmentBindings) {
		return deny()
	}
	// An existing original partial result is eligible only when that exact
	// canonical result names this receipt. Never select an unrelated old partial.
	firstRevision := old.ExpectedDeploymentRevision + 1
	var partialRaw []byte
	var partialDigest string
	completedErr := row(`SELECT canonical_bytes,digest FROM service_deployments WHERE plan_id=? AND run_id=?`, s.PriorPlanID, s.PriorRunID).Scan(&partialRaw, &partialDigest)
	if errors.Is(completedErr, sql.ErrNoRows) {
		if attemptStatus != "attempted" || effectState != "effect-unknown" {
			return deny()
		}
	} else {
		var partial generated.ServiceDeploymentRecord
		if completedErr != nil || attemptStatus != "partial" || json.Unmarshal(partialRaw, &partial) != nil || servicecatalog.Digest(partial) != partialDigest || partial.Status != "partial" || partial.PlanID != s.PriorPlanID || partial.RunID != s.PriorRunID || servicecatalog.Digest(partial.Request) != s.PriorRequestDigest || partial.ProviderReceiptID != s.ProviderReceiptID || partial.Revision != firstRevision || partial.Revision > q.ExpectedDeploymentRevision {
			return deny()
		}
		firstRevision++
	}
	// Failed observation-only attempts may append partial records, but cannot
	// make an unrelated deployment eligible or rewrite the original attempt.
	if q.ExpectedDeploymentRevision-old.ExpectedDeploymentRevision > 128 {
		return deny()
	}
	for revision := firstRevision; revision <= q.ExpectedDeploymentRevision; revision++ {
		var recordRaw []byte
		var recordDigest string
		var record generated.ServiceDeploymentRecord
		if row(`SELECT canonical_bytes,digest FROM service_deployments WHERE service_id=? AND revision=? AND recovery_epoch=? AND status='partial'`, q.Definition.ServiceID, revision, q.RecoveryEpoch).Scan(&recordRaw, &recordDigest) != nil || json.Unmarshal(recordRaw, &record) != nil || servicecatalog.Digest(record) != recordDigest || record.Status != "partial" || record.Revision != revision || record.Request.RecoveryEpoch != q.RecoveryEpoch || record.Request.Action != "reconcile" || record.Request.Recovery == nil || servicecatalog.Digest(record.Request.Recovery) != servicecatalog.Digest(q.Recovery) || record.Request.Definition != q.Definition || record.Request.Artifact != q.Artifact || record.Request.Binding != q.Binding || servicecatalog.Digest(record.Request.Configuration) != servicecatalog.Digest(q.Configuration) || servicecatalog.Digest(record.Request.EnvironmentBindings) != servicecatalog.Digest(q.EnvironmentBindings) {
			return deny()
		}
	}
	out.StartedAt, err = time.Parse(time.RFC3339Nano, started)
	if err != nil {
		return deny()
	}
	out.FinishedAt, err = time.Parse(time.RFC3339Nano, finished)
	if err != nil || out.FinishedAt.Before(out.StartedAt) || out.StartedAt.IsZero() {
		return deny()
	}
	out.Request = old
	out.PlanDigest = runDigest
	return out, nil
}

// Recovery linkage is encoded in the new immutable request, not a fabricated
// completion of the old callback. This update settles only its unknown attempt.
func settleDeploymentRecovery(ctx context.Context, tx *sql.Tx, q generated.ServiceDeploymentRequest) error {
	if q.Action != "reconcile" {
		return nil
	}
	s := q.Recovery
	result, err := tx.ExecContext(ctx, `UPDATE service_deployment_attempts SET status='partial' WHERE plan_id=? AND run_id=? AND step_id=? AND request_digest=? AND service_id=? AND recovery_epoch=? AND status IN ('attempted','partial')`, s.PriorPlanID, s.PriorRunID, s.PriorStepID, s.PriorRequestDigest, q.Definition.ServiceID, q.RecoveryEpoch)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return actionError(generated.ErrorCodeStateConflict)
	}
	return nil
}
