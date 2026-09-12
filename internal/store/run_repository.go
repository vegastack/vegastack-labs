package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

const (
	runDetailRetention  = 30 * 24 * time.Hour
	runSummaryRetention = 180 * 24 * time.Hour
)

var runTokenPattern = regexp.MustCompile(`^[a-z][a-z0-9._:-]{0,127}$`)

type RunCreateRequest struct {
	Run             generated.Run
	SubmitKeyDigest audit.Fingerprint
	RequestDigest   audit.Fingerprint
	Attribution     audit.Attribution
}

type RunCreateResult struct {
	Run     generated.Run
	Created bool
	EventID audit.EventID
}

type RunTransitionRequest struct {
	RunID              string
	From               string
	To                 string
	At                 time.Time
	VerificationStatus string
	VerificationDigest *string
	RollbackStatus     string
	Changed            *bool
	Attribution        audit.Attribution
}

type StepBeginRequest struct {
	RunID, StepID, LeaseID string
	At                     time.Time
	Attribution            audit.Attribution
}

type StepFinishRequest struct {
	RunID, StepID, LeaseID string
	Receipt                generated.ExecutionReceipt
	Status                 string
	EffectState            string
	VerificationDigest     string
	Changed                bool
	At                     time.Time
	Attribution            audit.Attribution
}

type ReceiptRecordRequest struct {
	RunID, StepID, LeaseID string
	Receipt                generated.ExecutionReceipt
	At                     time.Time
	Attribution            audit.Attribution
}

type RunEventRequest struct {
	RunID, EventType string
	EventDigest      audit.Fingerprint
	OccurredAt       time.Time
	Attribution      audit.Attribution
}

type RunPruneResult struct {
	DetailedEventsDeleted int64
	SummariesDeleted      int64
}

type RunOperationResult struct {
	Run       generated.Run
	Created   bool
	Completed bool
	ErrorCode string
}

type RunRepository struct{ store *Store }

func NewRunRepository(store *Store) *RunRepository { return &RunRepository{store: store} }

func (repository *RunRepository) Create(ctx context.Context, request RunCreateRequest) (RunCreateResult, error) {
	if repository == nil || repository.store == nil || request.Run.Status != "queued" || request.Run.CancellationRequested || request.Run.RollbackStatus != "not-requested" || request.Run.VerificationStatus != "pending" || request.Run.VerificationDigest != nil || !validRunDocument(request.Run) || audit.ValidateIntentKey(audit.IntentKey{Scope: "run-submit", KeyDigest: request.SubmitKeyDigest, RequestDigest: request.RequestDigest}) != nil {
		return RunCreateResult{}, newStoreError(generated.ErrorCodeInputInvalid, "run", false, nil)
	}
	if existing, found, err := repository.existing(ctx, request.SubmitKeyDigest, request.RequestDigest); err != nil || found {
		return existing, err
	}
	canonical, _ := json.Marshal(request.Run)
	fingerprint := runFingerprint(request.Run)
	event := audit.EventDraft{Type: "run.created", CorrelationID: request.Run.RunID, Attribution: request.Attribution, Target: audit.Target{Kind: "run", ID: request.Run.RunID}, After: &fingerprint}
	expected := RevisionToken{StateRevision: request.Run.StateRevision, RecoveryEpoch: request.Run.RecoveryEpoch}
	intent, err := repository.store.executeAuditIntent(ctx, intentRequest{Expected: &expected, Idempotency: audit.IntentKey{Scope: "run-submit", KeyDigest: request.SubmitKeyDigest, RequestDigest: request.RequestDigest}, Event: event}, false, func(ctx context.Context, transaction *sql.Tx) error {
		if err := verifyPlanBindingInTx(ctx, transaction, request.Run); err != nil {
			return err
		}
		_, err := transaction.ExecContext(ctx, `INSERT INTO plan_runs(run_id,plan_id,plan_digest,authorization_decision_id,acknowledgement_id,policy_version,executor_mode,executor_id,executor_binding_digest,status,cancellation_requested,rollback_status,verification_status,verification_digest,changed,state_revision,recovery_epoch,submit_key_digest,request_digest,canonical_bytes,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			request.Run.RunID, request.Run.PlanID, request.Run.PlanDigest, request.Run.AuthorizationDecisionID, request.Run.AcknowledgementID, request.Run.PolicyVersion, request.Run.ExecutorMode, request.Run.ExecutorID, request.Run.ExecutorBindingDigest, request.Run.Status, request.Run.CancellationRequested, request.Run.RollbackStatus, request.Run.VerificationStatus, request.Run.VerificationDigest, request.Run.Changed, request.Run.StateRevision, request.Run.RecoveryEpoch, request.SubmitKeyDigest, request.RequestDigest, canonical, request.Run.CreatedAt, request.Run.UpdatedAt)
		if err != nil {
			return err
		}
		for _, step := range request.Run.Steps {
			if _, err := transaction.ExecContext(ctx, `INSERT INTO plan_run_steps(step_id,run_id,sequence,operation_id,operation_type,adapter_id,executor_id,target_id,input_digest,artifact_digest,idempotent,status,effect_state) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, step.StepID, request.Run.RunID, step.Sequence, step.OperationID, step.OperationType, step.AdapterID, step.ExecutorID, step.TargetID, step.InputDigest, step.ArtifactDigest, step.Idempotent, step.Status, step.EffectState); err != nil {
				return err
			}
		}
		_, err = transaction.ExecContext(ctx, `INSERT INTO run_detail_events(run_id,event_type,event_digest,occurred_at) VALUES(?,?,?,?)`, request.Run.RunID, event.Type, fingerprint, request.Run.CreatedAt)
		return err
	})
	if err != nil {
		return RunCreateResult{}, err
	}
	if !intent.Created {
		return repository.existingRequired(ctx, request.SubmitKeyDigest, request.RequestDigest)
	}
	return RunCreateResult{Run: request.Run, Created: true, EventID: intent.EventID}, nil
}

func (repository *RunRepository) Get(ctx context.Context, runID string) (generated.Run, error) {
	if repository == nil || repository.store == nil || !validRunToken(runID) {
		return generated.Run{}, newStoreError(generated.ErrorCodeInputInvalid, "run", false, nil)
	}
	var canonical []byte
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT canonical_bytes FROM plan_runs WHERE run_id=?`, runID).Scan(&canonical)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return generated.Run{}, newStoreError(generated.ErrorCodeResourceNotFound, "run", false, nil)
	}
	if err != nil {
		return generated.Run{}, err
	}
	return decodeRun(canonical)
}

func (repository *RunRepository) GetRun(ctx context.Context, runID string) (generated.Run, error) {
	return repository.Get(ctx, runID)
}

func (repository *RunRepository) ClaimRunOperation(ctx context.Context, operation, runID string, keyDigest, requestDigest audit.Fingerprint, at time.Time, attribution audit.Attribution) (RunOperationResult, error) {
	if repository == nil || repository.store == nil || !validRunOperation(operation) || !validRunToken(runID) || at.IsZero() || at.Location() != time.UTC || audit.ValidateIntentKey(audit.IntentKey{Scope: "run-operation", KeyDigest: keyDigest, RequestDigest: requestDigest}) != nil {
		return RunOperationResult{}, newStoreError(generated.ErrorCodeInputInvalid, "run-operation", false, nil)
	}
	intentKey := digestParts("run-operation-claim", operation, runID, string(keyDigest))
	eventAfter := digestParts("run-operation", operation, runID, string(keyDigest))
	event := audit.EventDraft{Type: "run.operation-claimed", CorrelationID: runID, Attribution: attribution, Target: audit.Target{Kind: "run", ID: runID}, After: &eventAfter}
	intent, err := repository.store.executeAuditIntent(ctx, intentRequest{Idempotency: audit.IntentKey{Scope: "run-operation-claim", KeyDigest: intentKey, RequestDigest: requestDigest}, Event: event}, false, func(ctx context.Context, transaction *sql.Tx) error {
		var exists int
		if err := transaction.QueryRowContext(ctx, `SELECT COUNT(*) FROM plan_runs WHERE run_id=?`, runID).Scan(&exists); err != nil || exists != 1 {
			return newStoreError(generated.ErrorCodeResourceNotFound, "run", false, err)
		}
		_, err := transaction.ExecContext(ctx, `INSERT INTO run_operation_keys(operation,run_id,key_digest,request_digest,status,result_bytes,error_code,created_at,completed_at) VALUES(?,?,?,?,'pending',NULL,'',?,NULL)`, operation, runID, keyDigest, requestDigest, at.Format(time.RFC3339))
		return err
	})
	if err != nil {
		return RunOperationResult{}, err
	}
	result, err := repository.runOperation(ctx, operation, runID, keyDigest, requestDigest)
	result.Created = intent.Created
	return result, err
}

func (repository *RunRepository) CompleteRunOperation(ctx context.Context, operation, runID string, keyDigest, requestDigest audit.Fingerprint, run generated.Run, errorCode string, at time.Time, attribution audit.Attribution) (RunOperationResult, error) {
	if repository == nil || repository.store == nil || !validRunOperation(operation) || run.RunID != runID || !validRunDocument(run) || len(errorCode) > 64 || at.IsZero() || at.Location() != time.UTC {
		return RunOperationResult{}, newStoreError(generated.ErrorCodeInputInvalid, "run-operation", false, nil)
	}
	raw, _ := json.Marshal(run)
	resultDigest := digestParts("run-operation-result", operation, runID, string(keyDigest), string(requestDigest), string(raw), errorCode)
	event := audit.EventDraft{Type: "run.operation-completed", CorrelationID: runID, Attribution: attribution, Target: audit.Target{Kind: "run", ID: runID}, After: &resultDigest}
	_, err := repository.store.executeAuditIntent(ctx, intentRequest{Idempotency: audit.IntentKey{Scope: "run-operation-complete", KeyDigest: digestParts("run-operation-complete", operation, runID, string(keyDigest)), RequestDigest: resultDigest}, Event: event}, false, func(ctx context.Context, transaction *sql.Tx) error {
		result, err := transaction.ExecContext(ctx, `UPDATE run_operation_keys SET status='completed',result_bytes=?,error_code=?,completed_at=? WHERE operation=? AND run_id=? AND key_digest=? AND request_digest=? AND status='pending'`, raw, errorCode, at.Format(time.RFC3339), operation, runID, keyDigest, requestDigest)
		if err != nil {
			return err
		}
		rows, err := result.RowsAffected()
		if err != nil || rows != 1 {
			return newStoreError(generated.ErrorCodeStateConflict, "run-operation", false, err)
		}
		return nil
	})
	if err != nil {
		return RunOperationResult{}, err
	}
	return repository.runOperation(ctx, operation, runID, keyDigest, requestDigest)
}

func (repository *RunRepository) runOperation(ctx context.Context, operation, runID string, keyDigest, requestDigest audit.Fingerprint) (RunOperationResult, error) {
	var status, storedRequest, errorCode string
	var raw []byte
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT status,request_digest,result_bytes,error_code FROM run_operation_keys WHERE operation=? AND run_id=? AND key_digest=?`, operation, runID, keyDigest).Scan(&status, &storedRequest, &raw, &errorCode)
	})
	if err != nil {
		return RunOperationResult{}, err
	}
	if storedRequest != string(requestDigest) {
		return RunOperationResult{}, newStoreError(generated.ErrorCodeStateConflict, "run-operation-key", false, nil)
	}
	result := RunOperationResult{Completed: status == "completed", ErrorCode: errorCode}
	if result.Completed {
		run, err := decodeRun(raw)
		if err != nil {
			return RunOperationResult{}, err
		}
		result.Run = run
	}
	return result, nil
}

func (repository *RunRepository) TransitionRun(ctx context.Context, request RunTransitionRequest) (generated.Run, error) {
	if !validRunToken(request.RunID) || request.At.IsZero() || request.At.Location() != time.UTC || generated.ValidateRunTransition(request.From, request.To) != nil {
		return generated.Run{}, newStoreError(generated.ErrorCodeStateConflict, "run-transition", false, nil)
	}
	return repository.mutateRun(ctx, request.RunID, "run.transitioned", strings.Join([]string{request.From, request.To, request.At.Format(time.RFC3339Nano)}, ":"), request.Attribution, func(run *generated.Run, transaction *sql.Tx) error {
		if run.Status != request.From {
			return newStoreError(generated.ErrorCodeStateConflict, "run-transition", false, nil)
		}
		run.Status = request.To
		run.UpdatedAt = request.At.UTC().Truncate(time.Second).Format(time.RFC3339)
		if request.From == "interrupted" && request.To == "running" {
			for index := range run.Steps {
				step := &run.Steps[index]
				if step.Status != "interrupted" {
					continue
				}
				if !step.Idempotent || step.EffectState != "not-started" {
					return newStoreError(generated.ErrorCodeRecoveryRequired, "run-resume", false, nil)
				}
				step.Status = "queued"
				if _, err := transaction.ExecContext(ctx, `UPDATE plan_run_steps SET status='queued' WHERE run_id=? AND step_id=? AND status='interrupted' AND effect_state='not-started'`, run.RunID, step.StepID); err != nil {
					return err
				}
			}
		}
		if request.To == "cancelled" || request.To == "interrupted" || request.To == "failed" || request.To == "partial" {
			stepStatus := "interrupted"
			if request.To == "cancelled" {
				stepStatus = "cancelled"
			}
			for index := range run.Steps {
				step := &run.Steps[index]
				if step.Status != "queued" {
					continue
				}
				step.Status = stepStatus
				if _, err := transaction.ExecContext(ctx, `UPDATE plan_run_steps SET status=? WHERE run_id=? AND step_id=? AND status='queued'`, stepStatus, run.RunID, step.StepID); err != nil {
					return err
				}
			}
		}
		if request.VerificationStatus != "" {
			run.VerificationStatus = request.VerificationStatus
			run.VerificationDigest = request.VerificationDigest
		}
		if request.RollbackStatus != "" {
			run.RollbackStatus = request.RollbackStatus
		}
		if request.Changed != nil {
			run.Changed = *request.Changed
		}
		return nil
	})
}

func (repository *RunRepository) RequestCancellation(ctx context.Context, runID string, at time.Time, attribution audit.Attribution) (generated.Run, error) {
	if at.IsZero() || at.Location() != time.UTC {
		return generated.Run{}, newStoreError(generated.ErrorCodeInputInvalid, "run-cancellation", false, nil)
	}
	return repository.mutateRun(ctx, runID, "run.cancellation-requested", at.Format(time.RFC3339Nano), attribution, func(run *generated.Run, _ *sql.Tx) error {
		if terminalRunStatus(run.Status) {
			return newStoreError(generated.ErrorCodeStateConflict, "run-cancellation", false, nil)
		}
		run.CancellationRequested = true
		run.UpdatedAt = at.UTC().Truncate(time.Second).Format(time.RFC3339)
		return nil
	})
}

func (repository *RunRepository) AcquireTargetLease(ctx context.Context, lease generated.ExecutorLease, attribution audit.Attribution) error {
	if repository == nil || repository.store == nil || !validLease(lease) {
		return newStoreError(generated.ErrorCodeInputInvalid, "target-lease", false, nil)
	}
	canonical, _ := json.Marshal(lease)
	requestDigest := digestParts("target-lease", lease.LeaseID, lease.BindingDigest, lease.NonceDigest)
	event := audit.EventDraft{Type: "run.lease-acquired", CorrelationID: lease.RunID, Attribution: attribution, Target: audit.Target{Kind: "run", ID: lease.RunID}, After: ptrFingerprint(audit.Fingerprint(lease.BindingDigest))}
	_, err := repository.store.executeAuditIntent(ctx, intentRequest{Idempotency: audit.IntentKey{Scope: "run-lease", KeyDigest: digestParts("lease-key", lease.LeaseID), RequestDigest: requestDigest}, Event: event}, false, func(ctx context.Context, transaction *sql.Tx) error {
		run, plan, err := runAndPlanInTx(ctx, transaction, lease.RunID)
		if err != nil {
			return err
		}
		if generated.ValidateExecutorLeaseBinding(plan, run, lease) != nil || run.Status != "running" || lease.Status != "active" {
			return newStoreError(generated.ErrorCodeStateConflict, "target-lease", false, nil)
		}
		_, err = transaction.ExecContext(ctx, `INSERT INTO target_execution_leases(lease_id,run_id,step_id,target_id,binding_digest,nonce_digest,recovery_epoch,claimed_at,renew_after,expires_at,maximum_expires_at,status,canonical_bytes) VALUES(?,?,?,?,?,?,?,?,?,?,?,? ,?)`, lease.LeaseID, lease.RunID, lease.StepID, lease.TargetID, lease.BindingDigest, lease.NonceDigest, lease.RecoveryEpoch, lease.ClaimedAt, lease.RenewAfter, lease.LeaseExpiresAt, lease.MaximumExpiresAt, lease.Status, canonical)
		return err
	})
	return err
}

func (repository *RunRepository) ReleaseTargetLease(ctx context.Context, leaseID string, at time.Time) error {
	if !validRunToken(leaseID) || at.IsZero() || at.Location() != time.UTC {
		return newStoreError(generated.ErrorCodeInputInvalid, "target-lease", false, nil)
	}
	repository.store.mu.Lock()
	defer repository.store.mu.Unlock()
	if err := repository.store.readyForTransaction(ctx); err != nil {
		return err
	}
	result, err := repository.store.conn.ExecContext(ctx, `UPDATE target_execution_leases SET status='released',canonical_bytes=CAST(json_set(canonical_bytes,'$.status','released') AS BLOB) WHERE lease_id=? AND status='active'`, leaseID)
	if err != nil {
		return classifySQLiteError(ctx, err)
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		return newStoreError(generated.ErrorCodeStateConflict, "target-lease", false, nil)
	}
	return nil
}

func (repository *RunRepository) ReleaseRunLeases(ctx context.Context, runID string, at time.Time) error {
	if !validRunToken(runID) || at.IsZero() || at.Location() != time.UTC {
		return newStoreError(generated.ErrorCodeInputInvalid, "target-lease", false, nil)
	}
	repository.store.mu.Lock()
	defer repository.store.mu.Unlock()
	if err := repository.store.readyForTransaction(ctx); err != nil {
		return err
	}
	_, err := repository.store.conn.ExecContext(ctx, `UPDATE target_execution_leases SET status='released',canonical_bytes=CAST(json_set(canonical_bytes,'$.status','released') AS BLOB) WHERE run_id=? AND status='active'`, runID)
	if err != nil {
		return classifySQLiteError(ctx, err)
	}
	return nil
}

func (repository *RunRepository) BeginStep(ctx context.Context, request StepBeginRequest) (generated.Run, error) {
	if request.At.IsZero() || request.At.Location() != time.UTC || !validRunToken(request.StepID) || !validRunToken(request.LeaseID) {
		return generated.Run{}, newStoreError(generated.ErrorCodeInputInvalid, "run-step", false, nil)
	}
	return repository.mutateRun(ctx, request.RunID, "run.step-intent-recorded", strings.Join([]string{request.StepID, request.LeaseID, request.At.Format(time.RFC3339Nano)}, ":"), request.Attribution, func(run *generated.Run, transaction *sql.Tx) error {
		step := findStep(run, request.StepID)
		if run.Status != "running" || step == nil || step.Status != "queued" || step.EffectState != "not-started" {
			return newStoreError(generated.ErrorCodeStateConflict, "run-step", false, nil)
		}
		var active int
		if err := transaction.QueryRowContext(ctx, `SELECT COUNT(*) FROM target_execution_leases WHERE lease_id=? AND run_id=? AND step_id=? AND status='active'`, request.LeaseID, request.RunID, request.StepID).Scan(&active); err != nil || active != 1 {
			return newStoreError(generated.ErrorCodeStateConflict, "run-step-lease", false, err)
		}
		step.Status, step.EffectState = "running", "intent-recorded"
		run.UpdatedAt = request.At.UTC().Truncate(time.Second).Format(time.RFC3339)
		_, err := transaction.ExecContext(ctx, `UPDATE plan_run_steps SET status='running',effect_state='intent-recorded',active_lease_id=?,started_at=? WHERE step_id=? AND run_id=? AND status='queued' AND effect_state='not-started'`, request.LeaseID, run.UpdatedAt, request.StepID, request.RunID)
		return err
	})
}

func (repository *RunRepository) FinishStep(ctx context.Context, request StepFinishRequest) (generated.Run, error) {
	if request.At.IsZero() || request.At.Location() != time.UTC || request.EffectState != "verified" || request.VerificationDigest == "" || !validReceipt(request.Receipt) || (request.Status != "succeeded" && request.Status != "failed" && request.Status != "partial") {
		return generated.Run{}, newStoreError(generated.ErrorCodeInputInvalid, "run-step-result", false, nil)
	}
	return repository.mutateRun(ctx, request.RunID, "run.step-finished", request.Receipt.ReceiptID, request.Attribution, func(run *generated.Run, transaction *sql.Tx) error {
		step := findStep(run, request.StepID)
		if step == nil || request.Receipt.RunID != run.RunID || request.Receipt.StepID != step.StepID || request.Receipt.LeaseID != request.LeaseID {
			return newStoreError(generated.ErrorCodeStateConflict, "run-step-result", false, nil)
		}
		if step.Status == request.Status && step.EffectState == request.EffectState {
			return verifyStoredReceipt(ctx, transaction, request.Receipt)
		}
		if step.Status != "running" || step.EffectState != "receipt-recorded" {
			return newStoreError(generated.ErrorCodeStateConflict, "run-step-result", false, nil)
		}
		if err := verifyStoredReceipt(ctx, transaction, request.Receipt); err != nil {
			return err
		}
		step.Status, step.EffectState = request.Status, request.EffectState
		run.Changed = run.Changed || request.Changed
		run.UpdatedAt = request.At.UTC().Truncate(time.Second).Format(time.RFC3339)
		_, err := transaction.ExecContext(ctx, `UPDATE plan_run_steps SET status=?,effect_state=?,result_digest=?,finished_at=? WHERE step_id=? AND run_id=? AND status='running' AND effect_state='receipt-recorded'`, request.Status, request.EffectState, request.VerificationDigest, run.UpdatedAt, step.StepID, run.RunID)
		return err
	})
}

func (repository *RunRepository) RecordReceipt(ctx context.Context, request ReceiptRecordRequest) (generated.Run, error) {
	if request.At.IsZero() || request.At.Location() != time.UTC || !validReceipt(request.Receipt) {
		return generated.Run{}, newStoreError(generated.ErrorCodeInputInvalid, "run-receipt", false, nil)
	}
	return repository.mutateRun(ctx, request.RunID, "run.step-receipt-recorded", request.Receipt.ReceiptID, request.Attribution, func(run *generated.Run, transaction *sql.Tx) error {
		step := findStep(run, request.StepID)
		if step == nil || request.Receipt.RunID != run.RunID || request.Receipt.StepID != step.StepID || request.Receipt.LeaseID != request.LeaseID {
			return newStoreError(generated.ErrorCodeStateConflict, "run-receipt", false, nil)
		}
		if step.EffectState == "receipt-recorded" {
			return verifyStoredReceipt(ctx, transaction, request.Receipt)
		}
		if step.Status != "running" || step.EffectState != "intent-recorded" {
			return newStoreError(generated.ErrorCodeStateConflict, "run-receipt", false, nil)
		}
		var leaseBytes []byte
		if err := transaction.QueryRowContext(ctx, `SELECT canonical_bytes FROM target_execution_leases WHERE lease_id=? AND run_id=? AND step_id=? AND status='active'`, request.LeaseID, run.RunID, step.StepID).Scan(&leaseBytes); err != nil {
			return newStoreError(generated.ErrorCodeStateConflict, "run-step-lease", false, err)
		}
		var lease generated.ExecutorLease
		if json.Unmarshal(leaseBytes, &lease) != nil || generated.ValidateExecutionReceiptBinding(lease, request.Receipt) != nil {
			return newStoreError(generated.ErrorCodeIntegrityFailure, "run-receipt-binding", false, nil)
		}
		receiptBytes, _ := json.Marshal(request.Receipt)
		if _, err := transaction.ExecContext(ctx, `INSERT INTO execution_receipts(receipt_id,lease_id,run_id,step_id,status,result_digest,canonical_bytes,recorded_at) VALUES(?,?,?,?,?,?,?,?)`, request.Receipt.ReceiptID, request.LeaseID, run.RunID, step.StepID, request.Receipt.Status, request.Receipt.ResultDigest, receiptBytes, request.Receipt.RecordedAt); err != nil {
			return err
		}
		step.EffectState = "receipt-recorded"
		run.UpdatedAt = request.At.UTC().Truncate(time.Second).Format(time.RFC3339)
		_, err := transaction.ExecContext(ctx, `UPDATE plan_run_steps SET effect_state='receipt-recorded',result_digest=? WHERE run_id=? AND step_id=? AND status='running' AND effect_state='intent-recorded'`, request.Receipt.ResultDigest, run.RunID, step.StepID)
		return err
	})
}

func (repository *RunRepository) MarkStepUnknown(ctx context.Context, runID, stepID string, at time.Time, attribution audit.Attribution) (generated.Run, error) {
	return repository.mutateRun(ctx, runID, "run.step-effect-unknown", strings.Join([]string{stepID, at.Format(time.RFC3339Nano)}, ":"), attribution, func(run *generated.Run, transaction *sql.Tx) error {
		step := findStep(run, stepID)
		if step == nil || step.Status != "running" || (step.EffectState != "intent-recorded" && step.EffectState != "receipt-recorded") {
			return newStoreError(generated.ErrorCodeStateConflict, "run-step", false, nil)
		}
		step.Status, step.EffectState = "partial", "effect-unknown"
		run.Changed, run.UpdatedAt = true, at.UTC().Truncate(time.Second).Format(time.RFC3339)
		_, err := transaction.ExecContext(ctx, `UPDATE plan_run_steps SET status='partial',effect_state='effect-unknown',finished_at=? WHERE run_id=? AND step_id=? AND status='running' AND effect_state IN ('intent-recorded','receipt-recorded')`, run.UpdatedAt, runID, stepID)
		return err
	})
}

func (repository *RunRepository) FailStepBeforeEffect(ctx context.Context, runID, stepID string, at time.Time, attribution audit.Attribution) (generated.Run, error) {
	return repository.mutateRun(ctx, runID, "run.step-failed-before-effect", strings.Join([]string{stepID, at.Format(time.RFC3339Nano)}, ":"), attribution, func(run *generated.Run, transaction *sql.Tx) error {
		step := findStep(run, stepID)
		if step == nil || step.Status != "running" || step.EffectState != "intent-recorded" {
			return newStoreError(generated.ErrorCodeStateConflict, "run-step", false, nil)
		}
		step.Status, step.EffectState = "failed", "not-started"
		run.UpdatedAt = at.UTC().Truncate(time.Second).Format(time.RFC3339)
		_, err := transaction.ExecContext(ctx, `UPDATE plan_run_steps SET status='failed',effect_state='not-started',finished_at=? WHERE run_id=? AND step_id=? AND status='running' AND effect_state='intent-recorded'`, run.UpdatedAt, runID, stepID)
		return err
	})
}

func (repository *RunRepository) InterruptStepBeforeEffect(ctx context.Context, runID, stepID string, at time.Time, attribution audit.Attribution) (generated.Run, error) {
	return repository.mutateRun(ctx, runID, "run.step-interrupted-before-effect", strings.Join([]string{stepID, at.Format(time.RFC3339Nano)}, ":"), attribution, func(run *generated.Run, transaction *sql.Tx) error {
		step := findStep(run, stepID)
		if step == nil || step.Status != "running" || step.EffectState != "intent-recorded" {
			return newStoreError(generated.ErrorCodeStateConflict, "run-step", false, nil)
		}
		step.Status, step.EffectState = "interrupted", "not-started"
		run.UpdatedAt = at.UTC().Truncate(time.Second).Format(time.RFC3339)
		_, err := transaction.ExecContext(ctx, `UPDATE plan_run_steps SET status='interrupted',effect_state='not-started',finished_at=? WHERE run_id=? AND step_id=? AND status='running' AND effect_state='intent-recorded'`, run.UpdatedAt, runID, stepID)
		return err
	})
}

func (repository *RunRepository) AppendRunEvent(ctx context.Context, request RunEventRequest) error {
	if !validRunToken(request.RunID) || !validRunToken(request.EventType) || request.OccurredAt.IsZero() || request.OccurredAt.Location() != time.UTC || !strings.HasPrefix(string(request.EventDigest), "sha256:") {
		return newStoreError(generated.ErrorCodeInputInvalid, "run-event", false, nil)
	}
	event := audit.EventDraft{Type: audit.EventType(request.EventType), CorrelationID: request.RunID, Attribution: request.Attribution, Target: audit.Target{Kind: "run", ID: request.RunID}, After: &request.EventDigest}
	_, err := repository.store.executeAuditIntent(ctx, intentRequest{Idempotency: audit.IntentKey{Scope: "run-detail", KeyDigest: digestParts("run-event-key", request.RunID, request.EventType, request.OccurredAt.Format(time.RFC3339Nano)), RequestDigest: request.EventDigest}, Event: event}, false, func(ctx context.Context, transaction *sql.Tx) error {
		_, err := transaction.ExecContext(ctx, `INSERT INTO run_detail_events(run_id,event_type,event_digest,occurred_at) VALUES(?,?,?,?)`, request.RunID, request.EventType, request.EventDigest, request.OccurredAt.Format(time.RFC3339))
		return err
	})
	return err
}

func (repository *RunRepository) PruneRunHistory(ctx context.Context, now time.Time) (RunPruneResult, error) {
	if repository == nil || repository.store == nil || now.IsZero() || now.Location() != time.UTC {
		return RunPruneResult{}, newStoreError(generated.ErrorCodeInputInvalid, "run-retention", false, nil)
	}
	repository.store.mu.Lock()
	defer repository.store.mu.Unlock()
	if err := repository.store.readyForTransaction(ctx); err != nil {
		return RunPruneResult{}, err
	}
	transaction, err := repository.store.conn.BeginTx(ctx, nil)
	if err != nil {
		return RunPruneResult{}, repository.store.transactionError(ctx, err)
	}
	defer func() { _ = transaction.Rollback() }()
	details, err := transaction.ExecContext(ctx, `DELETE FROM run_detail_events WHERE occurred_at < ?`, now.Add(-runDetailRetention).Format(time.RFC3339))
	if err != nil {
		return RunPruneResult{}, classifySQLiteError(ctx, err)
	}
	summaries, err := transaction.ExecContext(ctx, `DELETE FROM plan_runs WHERE updated_at < ? AND status IN ('succeeded','failed','partial','interrupted','cancelled')`, now.Add(-runSummaryRetention).Format(time.RFC3339))
	if err != nil {
		return RunPruneResult{}, classifySQLiteError(ctx, err)
	}
	if err := transaction.Commit(); err != nil {
		return RunPruneResult{}, repository.store.transactionError(ctx, err)
	}
	detailedCount, _ := details.RowsAffected()
	summaryCount, _ := summaries.RowsAffected()
	return RunPruneResult{DetailedEventsDeleted: detailedCount, SummariesDeleted: summaryCount}, nil
}

func (repository *RunRepository) ActiveRuns(ctx context.Context) ([]generated.Run, error) {
	var canonical [][]byte
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		rows, err := tx.query(ctx, `SELECT canonical_bytes FROM plan_runs WHERE status IN ('queued','running','interrupted') ORDER BY created_at,run_id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var value []byte
			if err := rows.Scan(&value); err != nil {
				return err
			}
			canonical = append(canonical, value)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	runs := make([]generated.Run, 0, len(canonical))
	for _, value := range canonical {
		run, err := decodeRun(value)
		if err != nil {
			return nil, err
		}
		runs = append(runs, run)
	}
	return runs, nil
}

func (repository *RunRepository) mutateRun(ctx context.Context, runID, eventType, mutationID string, attribution audit.Attribution, mutate func(*generated.Run, *sql.Tx) error) (generated.Run, error) {
	if repository == nil || repository.store == nil || !validRunToken(runID) || mutate == nil {
		return generated.Run{}, newStoreError(generated.ErrorCodeInputInvalid, "run", false, nil)
	}
	var updated generated.Run
	key := digestParts("run-mutation-key", runID, eventType, mutationID)
	afterEvent := digestParts("run-mutation-event", runID, eventType, mutationID)
	event := audit.EventDraft{Type: audit.EventType(eventType), CorrelationID: runID, Attribution: attribution, Target: audit.Target{Kind: "run", ID: runID}, After: &afterEvent}
	intent, err := repository.store.executeAuditIntent(ctx, intentRequest{Idempotency: audit.IntentKey{Scope: "run-mutation", KeyDigest: key, RequestDigest: digestParts("run-mutation-request", runID, eventType, mutationID)}, Event: event}, false, func(ctx context.Context, transaction *sql.Tx) error {
		var canonical []byte
		if err := transaction.QueryRowContext(ctx, `SELECT canonical_bytes FROM plan_runs WHERE run_id=?`, runID).Scan(&canonical); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return newStoreError(generated.ErrorCodeResourceNotFound, "run", false, nil)
			}
			return err
		}
		run, err := decodeRun(canonical)
		if err != nil {
			return err
		}
		if err := mutate(&run, transaction); err != nil {
			return err
		}
		if !validRunDocument(run) {
			return newStoreError(generated.ErrorCodeIntegrityFailure, "run", false, nil)
		}
		encoded, _ := json.Marshal(run)
		result, err := transaction.ExecContext(ctx, `UPDATE plan_runs SET status=?,cancellation_requested=?,rollback_status=?,verification_status=?,verification_digest=?,changed=?,canonical_bytes=?,updated_at=? WHERE run_id=?`, run.Status, run.CancellationRequested, run.RollbackStatus, run.VerificationStatus, run.VerificationDigest, run.Changed, encoded, run.UpdatedAt, run.RunID)
		if err != nil {
			return err
		}
		rows, _ := result.RowsAffected()
		if rows != 1 {
			return newStoreError(generated.ErrorCodeStateConflict, "run", false, nil)
		}
		after := runFingerprint(run)
		_, err = transaction.ExecContext(ctx, `INSERT INTO run_detail_events(run_id,event_type,event_digest,occurred_at) VALUES(?,?,?,?)`, run.RunID, eventType, after, run.UpdatedAt)
		updated = run
		return err
	})
	if err == nil && !intent.Created {
		return repository.Get(ctx, runID)
	}
	return updated, err
}

func (repository *RunRepository) existing(ctx context.Context, key, requestDigest audit.Fingerprint) (RunCreateResult, bool, error) {
	var storedRequest string
	var canonical []byte
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT request_digest,canonical_bytes FROM plan_runs WHERE submit_key_digest=?`, key).Scan(&storedRequest, &canonical)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return RunCreateResult{}, false, nil
	}
	if err != nil {
		return RunCreateResult{}, false, err
	}
	if storedRequest != string(requestDigest) {
		return RunCreateResult{}, true, newStoreError(generated.ErrorCodeStateConflict, "run-submit-key", false, nil)
	}
	run, err := decodeRun(canonical)
	return RunCreateResult{Run: run, Created: false}, true, err
}

func (repository *RunRepository) existingRequired(ctx context.Context, key, request audit.Fingerprint) (RunCreateResult, error) {
	result, found, err := repository.existing(ctx, key, request)
	if err != nil {
		return RunCreateResult{}, err
	}
	if !found {
		return RunCreateResult{}, newStoreError(generated.ErrorCodeIntegrityFailure, "run", false, nil)
	}
	return result, nil
}

func verifyPlanBindingInTx(ctx context.Context, transaction *sql.Tx, run generated.Run) error {
	var planDigest string
	var stateRevision, recoveryEpoch int64
	if err := transaction.QueryRowContext(ctx, `SELECT plan_digest,state_revision,recovery_epoch FROM immutable_plans WHERE plan_id=?`, run.PlanID).Scan(&planDigest, &stateRevision, &recoveryEpoch); err != nil {
		return newStoreError(generated.ErrorCodePlanStale, "plan", false, err)
	}
	if planDigest != run.PlanDigest || stateRevision != run.StateRevision || recoveryEpoch != run.RecoveryEpoch {
		return newStoreError(generated.ErrorCodePlanStale, "plan", false, nil)
	}
	return nil
}

func runAndPlanInTx(ctx context.Context, transaction *sql.Tx, runID string) (generated.Run, generated.Plan, error) {
	var runBytes, planBytes []byte
	if err := transaction.QueryRowContext(ctx, `SELECT r.canonical_bytes,p.canonical_bytes FROM plan_runs r JOIN immutable_plans p ON p.plan_id=r.plan_id WHERE r.run_id=?`, runID).Scan(&runBytes, &planBytes); err != nil {
		return generated.Run{}, generated.Plan{}, newStoreError(generated.ErrorCodeResourceNotFound, "run", false, err)
	}
	run, err := decodeRun(runBytes)
	if err != nil {
		return generated.Run{}, generated.Plan{}, err
	}
	var plan generated.Plan
	if json.Unmarshal(planBytes, &plan) != nil || generated.ValidateContractJSON(generated.SchemaIDPlan, planBytes, generated.ContractExact) != nil {
		return generated.Run{}, generated.Plan{}, newStoreError(generated.ErrorCodeIntegrityFailure, "plan", false, nil)
	}
	return run, plan, nil
}

func validRunDocument(run generated.Run) bool {
	raw, err := json.Marshal(run)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDRun, raw, generated.ContractExact) != nil || !validRunToken(run.RunID) || len(run.Steps) == 0 {
		return false
	}
	seenSteps, seenOps := map[string]bool{}, map[string]bool{}
	steps := append([]generated.RunStep(nil), run.Steps...)
	sort.Slice(steps, func(i, j int) bool { return steps[i].Sequence < steps[j].Sequence })
	for index, step := range steps {
		if step.Sequence != int64(index+1) || seenSteps[step.StepID] || seenOps[step.OperationID] {
			return false
		}
		seenSteps[step.StepID], seenOps[step.OperationID] = true, true
	}
	return true
}

func decodeRun(canonical []byte) (generated.Run, error) {
	var run generated.Run
	if json.Unmarshal(canonical, &run) != nil || !validRunDocument(run) {
		return generated.Run{}, newStoreError(generated.ErrorCodeIntegrityFailure, "run", false, nil)
	}
	reencoded, _ := json.Marshal(run)
	if string(reencoded) != string(canonical) {
		return generated.Run{}, newStoreError(generated.ErrorCodeIntegrityFailure, "run", false, nil)
	}
	return run, nil
}

func validLease(lease generated.ExecutorLease) bool {
	raw, err := json.Marshal(lease)
	return err == nil && generated.ValidateContractJSON(generated.SchemaIDExecutorLease, raw, generated.ContractExact) == nil && generated.ValidateLeaseTiming(lease) == nil
}

func validReceipt(receipt generated.ExecutionReceipt) bool {
	raw, err := json.Marshal(receipt)
	return err == nil && generated.ValidateContractJSON(generated.SchemaIDExecutionReceipt, raw, generated.ContractExact) == nil
}

func findStep(run *generated.Run, stepID string) *generated.RunStep {
	for index := range run.Steps {
		if run.Steps[index].StepID == stepID {
			return &run.Steps[index]
		}
	}
	return nil
}

func verifyStoredReceipt(ctx context.Context, transaction *sql.Tx, receipt generated.ExecutionReceipt) error {
	var existing []byte
	if err := transaction.QueryRowContext(ctx, `SELECT canonical_bytes FROM execution_receipts WHERE receipt_id=?`, receipt.ReceiptID).Scan(&existing); err != nil {
		return newStoreError(generated.ErrorCodeStateConflict, "run-receipt", false, err)
	}
	expected, _ := json.Marshal(receipt)
	if string(existing) != string(expected) {
		return newStoreError(generated.ErrorCodeStateConflict, "run-receipt", false, nil)
	}
	return nil
}

func terminalRunStatus(status string) bool {
	return status == "succeeded" || status == "failed" || status == "partial" || status == "cancelled"
}
func validRunToken(value string) bool {
	return runTokenPattern.MatchString(value)
}
func validRunOperation(value string) bool { return value == "cancel" || value == "resume" }
func runFingerprint(run generated.Run) audit.Fingerprint {
	raw, _ := json.Marshal(run)
	sum := sha256.Sum256(raw)
	return audit.Fingerprint("sha256:" + hex.EncodeToString(sum[:]))
}
func digestParts(parts ...string) audit.Fingerprint {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return audit.Fingerprint("sha256:" + hex.EncodeToString(sum[:]))
}
func ptrFingerprint(value audit.Fingerprint) *audit.Fingerprint { return &value }
