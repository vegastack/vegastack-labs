package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

type RecoveryCanaryNoopRequest struct {
	PlanID, PlanDigest, RunID, StepID, LeaseID string
	InstanceID, ResultDigest                   string
	RecoveryEpoch, StateRevision               int64
	Attribution                                audit.Attribution
}

// RecordRecoveryCanaryNoop is the single narrow write admitted before normal
// mutation resumes. It accepts only the identifiers already sealed into the
// recovered, human-acknowledged restore bundle and appends an audit event.
func (store *Store) RecordRecoveryCanaryNoop(ctx context.Context, request RecoveryCanaryNoopRequest) error {
	if store == nil || request.PlanID == "" || request.RunID == "" || request.StepID == "" || request.LeaseID == "" || request.InstanceID == "" ||
		!restoreDigest(request.PlanDigest) || !restoreDigest(request.ResultDigest) || request.RecoveryEpoch < 1 || request.StateRevision < 0 {
		return newStoreError(generated.ErrorCodeInputInvalid, "recovery-canary-noop", false, nil)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.readyForRead(ctx); err != nil {
		return err
	}
	transaction, err := store.conn.BeginTx(ctx, nil)
	if err != nil {
		return store.transactionError(ctx, err)
	}
	defer transaction.Rollback()
	var instance, mode string
	var epoch, revision int64
	if err := transaction.QueryRowContext(ctx, `SELECT instance_id,recovery_epoch,state_revision,authority_mode FROM system_meta WHERE id=1`).Scan(&instance, &epoch, &revision, &mode); err != nil || instance != request.InstanceID || epoch != request.RecoveryEpoch || revision != request.StateRevision || mode != "recovery-required" {
		return newStoreError(generated.ErrorCodeRecoveryRequired, "recovery-canary-noop", false, err)
	}
	var planDigest, bindingRun, bindingStep, bindingLease string
	if err := transaction.QueryRowContext(ctx, `SELECT plan_digest,json_extract(binding_bytes,'$.canaryRunId'),json_extract(binding_bytes,'$.canaryStepId'),json_extract(binding_bytes,'$.canaryLeaseId') FROM recovery_authority_bundles WHERE plan_id=? AND status='verification-required'`, request.PlanID).Scan(&planDigest, &bindingRun, &bindingStep, &bindingLease); err != nil || planDigest != request.PlanDigest || bindingRun != request.RunID || bindingStep != request.StepID || bindingLease != request.LeaseID {
		return newStoreError(generated.ErrorCodePlanStale, "recovery-canary-noop", false, err)
	}
	event := audit.EventDraft{Type: "recovery.canary-noop-verified", CorrelationID: request.RunID, Attribution: request.Attribution, Target: audit.Target{Kind: "recovery", ID: request.InstanceID}, After: ptrFingerprint(audit.Fingerprint(request.ResultDigest))}
	intent := intentRequest{Expected: &RevisionToken{StateRevision: request.StateRevision, RecoveryEpoch: request.RecoveryEpoch}, Idempotency: audit.IntentKey{Scope: "recovery-canary-noop", KeyDigest: digestParts("recovery-canary-noop-key", request.PlanID, request.RunID), RequestDigest: audit.Fingerprint(request.ResultDigest)}, Event: event, Context: audit.ContextIDs{PlanID: request.PlanID, RunID: request.RunID}}
	result, err := store.appendAuditInTx(ctx, transaction, intent, false, func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO recovery_canary_runs(plan_id,plan_digest,run_id,step_id,lease_id,instance_id,recovery_epoch,state_revision,result_digest,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, request.PlanID, request.PlanDigest, request.RunID, request.StepID, request.LeaseID, request.InstanceID, request.RecoveryEpoch, request.StateRevision, request.ResultDigest, store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339))
		if err != nil {
			var existing string
			if readErr := tx.QueryRowContext(ctx, `SELECT result_digest FROM recovery_canary_runs WHERE plan_id=? AND run_id=? AND step_id=? AND lease_id=?`, request.PlanID, request.RunID, request.StepID, request.LeaseID).Scan(&existing); readErr == nil && existing == request.ResultDigest {
				return nil
			}
			return err
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return newStoreError(generated.ErrorCodePlanStale, "recovery-canary-noop", false, err)
		}
		return store.transactionError(ctx, err)
	}
	if err := store.checkIdentity(ctx); err != nil {
		return err
	}
	if err := transaction.Commit(); err != nil {
		return store.transactionError(ctx, err)
	}
	if result.Created {
		store.events.signal()
	}
	return nil
}
