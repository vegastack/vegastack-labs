package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

type ExecutorLeaseClaimRequest struct {
	Request     generated.ExecutorClaimRequest
	Lease       generated.ExecutorLease
	At          time.Time
	Attribution audit.Attribution
}

type ExecutorLeaseRenewalRequest struct {
	Request         generated.ExecutorRenewRequest
	NextNonceDigest string
	At              time.Time
	Attribution     audit.Attribution
}

type ExecutorLeaseExpiryRequest struct {
	At          time.Time
	Attribution audit.Attribution
}

type ExecutorReceiptPersistenceRequest struct {
	Request     generated.ExecutionReceiptRequest
	At          time.Time
	Attribution audit.Attribution
}

type ExecutorLeaseRepository struct{ store *Store }

func NewExecutorLeaseRepository(store *Store) *ExecutorLeaseRepository {
	return &ExecutorLeaseRepository{store: store}
}

// Claim persists the exact server-selected lease and intent-records its step in
// one transaction. Once this returns, an expired lease is always ambiguous and
// cannot be automatically reassigned by this repository.
func (repository *ExecutorLeaseRepository) Claim(ctx context.Context, request ExecutorLeaseClaimRequest) (generated.ExecutorLease, error) {
	if repository == nil || repository.store == nil || !validUTCSecond(request.At) || !validExecutorClaim(request.Request) || !validLease(request.Lease) {
		return generated.ExecutorLease{}, newStoreError(generated.ErrorCodeInputInvalid, "executor-lease-claim", false, nil)
	}
	lease := request.Lease
	if lease.Status != "active" || lease.ClaimedAt != request.At.Format(time.RFC3339) ||
		request.Request.ExecutorID != lease.ExecutorID || request.Request.AdapterID != lease.AdapterID ||
		request.Request.NonceDigest != lease.NonceDigest || request.Request.PrincipalID != request.Attribution.AuthenticatedPrincipalID {
		return generated.ExecutorLease{}, newStoreError(generated.ErrorCodeAuthorizationDenied, "executor-lease-claim", false, nil)
	}
	if request.Request.RecoveryEpoch != lease.RecoveryEpoch {
		return generated.ExecutorLease{}, newStoreError(generated.ErrorCodeRecoveryEpochMismatch, "executor-lease-claim", false, nil)
	}

	canonical, _ := json.Marshal(lease)
	event := audit.EventDraft{
		Type: "run.external-lease-claimed", CorrelationID: lease.RunID, Attribution: request.Attribution,
		Target: audit.Target{Kind: "executor-lease", ID: lease.LeaseID}, After: ptrFingerprint(audit.Fingerprint(lease.BindingDigest)),
	}
	intent, err := repository.store.executeAuditIntent(ctx, intentRequest{
		Idempotency: audit.IntentKey{Scope: "executor-lease-claim", KeyDigest: digestParts("executor-lease-claim-key", lease.LeaseID), RequestDigest: digestParts("executor-lease-claim", string(canonical), request.Request.PrincipalID)},
		Event:       event,
	}, false, func(ctx context.Context, transaction *sql.Tx) error {
		run, plan, err := runAndPlanInTx(ctx, transaction, lease.RunID)
		if err != nil {
			return err
		}
		if run.RecoveryEpoch != lease.RecoveryEpoch || plan.Binding.RecoveryEpoch != lease.RecoveryEpoch {
			return newStoreError(generated.ErrorCodeRecoveryEpochMismatch, "executor-lease-claim", false, nil)
		}
		if run.ExecutorMode != "external" || plan.ExecutorMode != "external" || generated.ValidateExecutorLeaseBinding(plan, run, lease) != nil {
			return newStoreError(generated.ErrorCodeAuthorizationDenied, "executor-lease-binding", false, nil)
		}
		step := findStep(&run, lease.StepID)
		if run.Status != "running" || step == nil || step.Status != "queued" || step.EffectState != "not-started" ||
			step.ExecutorID != lease.ExecutorID || step.AdapterID != lease.AdapterID || step.TargetID != lease.TargetID || step.ArtifactDigest != lease.ArtifactDigest {
			return newStoreError(generated.ErrorCodeStateConflict, "executor-lease-step", false, nil)
		}
		var prior int
		if err := transaction.QueryRowContext(ctx, `SELECT COUNT(*) FROM target_execution_leases WHERE step_id=?`, lease.StepID).Scan(&prior); err != nil {
			return err
		}
		if prior != 0 {
			return newStoreError(generated.ErrorCodeRecoveryRequired, "executor-lease-reconciliation", false, nil)
		}
		if _, err := transaction.ExecContext(ctx, `INSERT INTO target_execution_leases(lease_id,run_id,step_id,target_id,binding_digest,nonce_digest,recovery_epoch,claimed_at,renew_after,expires_at,maximum_expires_at,status,canonical_bytes,lease_kind,last_renewed_at,renewal_count) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,'external',NULL,0)`, lease.LeaseID, lease.RunID, lease.StepID, lease.TargetID, lease.BindingDigest, lease.NonceDigest, lease.RecoveryEpoch, lease.ClaimedAt, lease.RenewAfter, lease.LeaseExpiresAt, lease.MaximumExpiresAt, lease.Status, canonical); err != nil {
			return err
		}
		if _, err := transaction.ExecContext(ctx, `INSERT INTO executor_lease_nonce_history(lease_id,sequence,nonce_digest,accepted_at) VALUES(?,0,?,?)`, lease.LeaseID, lease.NonceDigest, lease.ClaimedAt); err != nil {
			return err
		}
		step.Status, step.EffectState = "running", "intent-recorded"
		run.UpdatedAt = request.At.Format(time.RFC3339)
		runBytes, _ := json.Marshal(run)
		stepResult, err := transaction.ExecContext(ctx, `UPDATE plan_run_steps SET status='running',effect_state='intent-recorded',active_lease_id=?,started_at=? WHERE step_id=? AND run_id=? AND status='queued' AND effect_state='not-started'`, lease.LeaseID, run.UpdatedAt, lease.StepID, lease.RunID)
		if err != nil {
			return err
		}
		if rows, _ := stepResult.RowsAffected(); rows != 1 {
			return newStoreError(generated.ErrorCodeStateConflict, "executor-lease-step", false, nil)
		}
		_, err = transaction.ExecContext(ctx, `UPDATE plan_runs SET canonical_bytes=?,updated_at=? WHERE run_id=? AND status='running'`, runBytes, run.UpdatedAt, run.RunID)
		return err
	})
	if err != nil {
		return generated.ExecutorLease{}, err
	}
	if !intent.Created {
		return generated.ExecutorLease{}, newStoreError(generated.ErrorCodeStateConflict, "executor-lease-claim-replay", false, nil)
	}
	return lease, nil
}

// Renew is a liveness check only. It rotates the one-time nonce and advances
// the next check-in time without extending the immutable 60-second authority.
func (repository *ExecutorLeaseRepository) Renew(ctx context.Context, request ExecutorLeaseRenewalRequest) (generated.ExecutorLease, error) {
	if repository == nil || repository.store == nil || !validUTCSecond(request.At) || !validExecutorRenewal(request.Request) || !audit.ValidFingerprint(audit.Fingerprint(request.NextNonceDigest)) || request.NextNonceDigest == request.Request.NonceDigest {
		return generated.ExecutorLease{}, newStoreError(generated.ErrorCodeInputInvalid, "executor-lease-renewal", false, nil)
	}
	event := audit.EventDraft{
		Type: "run.external-lease-renewed", CorrelationID: request.Request.LeaseID, Attribution: request.Attribution,
		Target: audit.Target{Kind: "executor-lease", ID: request.Request.LeaseID}, After: ptrFingerprint(audit.Fingerprint(request.Request.BindingDigest)),
	}
	var renewed generated.ExecutorLease
	intent, err := repository.store.executeAuditIntent(ctx, intentRequest{
		Idempotency: audit.IntentKey{Scope: "executor-lease-renew", KeyDigest: digestParts("executor-lease-renew-key", request.Request.LeaseID, request.Request.NonceDigest), RequestDigest: digestParts("executor-lease-renew", request.NextNonceDigest, request.At.Format(time.RFC3339))},
		Event:       event,
	}, false, func(ctx context.Context, transaction *sql.Tx) error {
		lease, status, renewalCount, err := readExecutorLeaseInTx(ctx, transaction, request.Request.LeaseID)
		if err != nil {
			return err
		}
		if request.Request.RecoveryEpoch != lease.RecoveryEpoch {
			return newStoreError(generated.ErrorCodeRecoveryEpochMismatch, "executor-lease-renewal", false, nil)
		}
		if request.Request.BindingDigest != lease.BindingDigest || request.Request.NonceDigest != lease.NonceDigest {
			return newStoreError(generated.ErrorCodeAuthorizationDenied, "executor-lease-renewal", false, nil)
		}
		var currentEpoch int64
		if err := transaction.QueryRowContext(ctx, `SELECT recovery_epoch FROM system_meta WHERE id=1`).Scan(&currentEpoch); err != nil {
			return err
		}
		if currentEpoch != lease.RecoveryEpoch {
			return newStoreError(generated.ErrorCodeRecoveryEpochMismatch, "executor-lease-renewal", false, nil)
		}
		renewAfter, expiry, err := executorLeaseTimes(lease)
		if err != nil {
			return err
		}
		if status != "active" || request.At.Before(renewAfter) || !request.At.Before(expiry) {
			return newStoreError(generated.ErrorCodeStateConflict, "executor-lease-renewal-window", false, nil)
		}
		nextRenewAfter := request.At.Add(time.Duration(generated.ExecutorCheckInSeconds) * time.Second)
		if nextRenewAfter.After(expiry) {
			nextRenewAfter = expiry
		}
		renewed = lease
		renewed.NonceDigest = request.NextNonceDigest
		renewed.RenewAfter = nextRenewAfter.Format(time.RFC3339)
		canonical, _ := json.Marshal(renewed)
		if _, err := transaction.ExecContext(ctx, `INSERT INTO executor_lease_nonce_history(lease_id,sequence,nonce_digest,accepted_at) VALUES(?,?,?,?)`, lease.LeaseID, renewalCount+1, request.NextNonceDigest, request.At.Format(time.RFC3339)); err != nil {
			return err
		}
		result, err := transaction.ExecContext(ctx, `UPDATE target_execution_leases SET nonce_digest=?,renew_after=?,last_renewed_at=?,renewal_count=renewal_count+1,canonical_bytes=? WHERE lease_id=? AND status='active' AND binding_digest=? AND nonce_digest=? AND recovery_epoch=?`, request.NextNonceDigest, renewed.RenewAfter, request.At.Format(time.RFC3339), canonical, lease.LeaseID, lease.BindingDigest, lease.NonceDigest, lease.RecoveryEpoch)
		if err != nil {
			return err
		}
		if rows, _ := result.RowsAffected(); rows != 1 {
			return newStoreError(generated.ErrorCodeStateConflict, "executor-lease-renewal", false, nil)
		}
		return nil
	})
	if err != nil {
		return generated.ExecutorLease{}, err
	}
	if !intent.Created {
		return generated.ExecutorLease{}, newStoreError(generated.ErrorCodeAuthorizationDenied, "executor-lease-renewal-replay", false, nil)
	}
	return renewed, nil
}

func (repository *ExecutorLeaseRepository) Expire(ctx context.Context, request ExecutorLeaseExpiryRequest) ([]generated.ExecutorLease, error) {
	if repository == nil || repository.store == nil || !validUTCSecond(request.At) {
		return nil, newStoreError(generated.ErrorCodeInputInvalid, "executor-lease-expiry", false, nil)
	}
	event := audit.EventDraft{
		Type: "run.external-leases-expired", CorrelationID: "external-lease-expiry", Attribution: request.Attribution,
		Target: audit.Target{Kind: "executor-leases", ID: "active"}, After: ptrFingerprint(digestParts("executor-lease-expiry", request.At.Format(time.RFC3339))),
	}
	expired := make([]generated.ExecutorLease, 0)
	intent, err := repository.store.executeAuditIntent(ctx, intentRequest{
		Idempotency: audit.IntentKey{Scope: "executor-lease-expire", KeyDigest: digestParts("executor-lease-expire-key", request.At.Format(time.RFC3339)), RequestDigest: digestParts("executor-lease-expire", request.At.Format(time.RFC3339))},
		Event:       event,
	}, false, func(ctx context.Context, transaction *sql.Tx) error {
		rows, err := transaction.QueryContext(ctx, `SELECT canonical_bytes FROM target_execution_leases WHERE lease_kind='external' AND status='active' AND expires_at<=? ORDER BY lease_id`, request.At.Format(time.RFC3339))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var canonical []byte
			if err := rows.Scan(&canonical); err != nil {
				return err
			}
			lease, err := decodeStoredExecutorLease(canonical)
			if err != nil {
				return err
			}
			lease.Status = "expired"
			expired = append(expired, lease)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		for _, lease := range expired {
			canonical, _ := json.Marshal(lease)
			result, err := transaction.ExecContext(ctx, `UPDATE target_execution_leases SET status='expired',canonical_bytes=? WHERE lease_id=? AND status='active'`, canonical, lease.LeaseID)
			if err != nil {
				return err
			}
			if rows, _ := result.RowsAffected(); rows != 1 {
				return newStoreError(generated.ErrorCodeStateConflict, "executor-lease-expiry", false, nil)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !intent.Created {
		return []generated.ExecutorLease{}, nil
	}
	return expired, nil
}

// RecordReceipt stores an exact receipt as an untrusted observation. Active or
// expired leases may report. Progress leaves the durable intent in place; a
// terminal receipt advances only to receipt-recorded for independent settling.
func (repository *ExecutorLeaseRepository) RecordReceipt(ctx context.Context, request ExecutorReceiptPersistenceRequest) (generated.ExecutionReceipt, error) {
	if repository == nil || repository.store == nil || !validUTCSecond(request.At) || !validExecutionReceiptRequest(request.Request) {
		return generated.ExecutionReceipt{}, newStoreError(generated.ErrorCodeInputInvalid, "executor-receipt", false, nil)
	}
	receipt := request.Request.Receipt
	if request.Request.ExpectedBindingDigest != receipt.BindingDigest {
		return generated.ExecutionReceipt{}, newStoreError(generated.ErrorCodeAuthorizationDenied, "executor-receipt-binding", false, nil)
	}
	recordedAt, err := time.Parse(time.RFC3339, receipt.RecordedAt)
	if err != nil || recordedAt.After(request.At) {
		return generated.ExecutionReceipt{}, newStoreError(generated.ErrorCodeInputInvalid, "executor-receipt-time", false, err)
	}
	receiptBytes, _ := json.Marshal(receipt)
	event := audit.EventDraft{
		Type: "run.external-receipt-recorded", CorrelationID: receipt.RunID, Attribution: request.Attribution,
		Target: audit.Target{Kind: "executor-lease", ID: receipt.LeaseID}, After: ptrFingerprint(audit.Fingerprint(receipt.ResultDigest)),
	}
	intent, err := repository.store.executeAuditIntent(ctx, intentRequest{
		Idempotency: audit.IntentKey{Scope: "executor-receipt", KeyDigest: digestParts("executor-receipt-key", receipt.ReceiptID), RequestDigest: digestParts("executor-receipt", string(receiptBytes), request.Request.ExpectedBindingDigest)},
		Event:       event,
	}, false, func(ctx context.Context, transaction *sql.Tx) error {
		lease, status, _, err := readExecutorLeaseInTx(ctx, transaction, receipt.LeaseID)
		if err != nil {
			return err
		}
		if receipt.RecoveryEpoch != lease.RecoveryEpoch {
			return newStoreError(generated.ErrorCodeRecoveryEpochMismatch, "executor-receipt", false, nil)
		}
		if generated.ValidateExecutionReceiptBinding(lease, receipt) != nil {
			return newStoreError(generated.ErrorCodeAuthorizationDenied, "executor-receipt-binding", false, nil)
		}
		_, expiry, err := executorLeaseTimes(lease)
		if err != nil {
			return err
		}
		if status == "active" && !request.At.Before(expiry) {
			lease.Status = "expired"
			leaseBytes, _ := json.Marshal(lease)
			if _, err := transaction.ExecContext(ctx, `UPDATE target_execution_leases SET status='expired',canonical_bytes=? WHERE lease_id=? AND status='active'`, leaseBytes, lease.LeaseID); err != nil {
				return err
			}
			status = "expired"
		}
		if status != "active" && status != "expired" {
			return newStoreError(generated.ErrorCodeAuthorizationDenied, "executor-receipt-lease", false, nil)
		}
		var currentEpoch int64
		if err := transaction.QueryRowContext(ctx, `SELECT recovery_epoch FROM system_meta WHERE id=1`).Scan(&currentEpoch); err != nil {
			return err
		}
		if currentEpoch != lease.RecoveryEpoch {
			return newStoreError(generated.ErrorCodeRecoveryEpochMismatch, "executor-receipt", false, nil)
		}
		var priorTerminal int
		if err := transaction.QueryRowContext(ctx, `SELECT COUNT(*) FROM external_execution_observations WHERE lease_id=? AND status!='running'`, receipt.LeaseID).Scan(&priorTerminal); err != nil {
			return err
		}
		if receipt.Status != "running" && priorTerminal != 0 {
			return newStoreError(generated.ErrorCodeStateConflict, "executor-receipt-terminal", false, nil)
		}
		if _, err := transaction.ExecContext(ctx, `INSERT INTO external_execution_observations(receipt_id,lease_id,run_id,step_id,status,result_digest,canonical_bytes,recorded_at) VALUES(?,?,?,?,?,?,?,?)`, receipt.ReceiptID, receipt.LeaseID, receipt.RunID, receipt.StepID, receipt.Status, receipt.ResultDigest, receiptBytes, receipt.RecordedAt); err != nil {
			return err
		}
		if receipt.Status == "running" {
			return nil
		}
		run, _, err := runAndPlanInTx(ctx, transaction, receipt.RunID)
		if err != nil {
			return err
		}
		step := findStep(&run, receipt.StepID)
		if step == nil || step.Status != "running" || step.EffectState != "intent-recorded" {
			return newStoreError(generated.ErrorCodeStateConflict, "executor-receipt-step", false, nil)
		}
		step.EffectState = "receipt-recorded"
		run.UpdatedAt = request.At.Format(time.RFC3339)
		runBytes, _ := json.Marshal(run)
		stepResult, err := transaction.ExecContext(ctx, `UPDATE plan_run_steps SET effect_state='receipt-recorded',result_digest=? WHERE run_id=? AND step_id=? AND status='running' AND effect_state='intent-recorded'`, receipt.ResultDigest, receipt.RunID, receipt.StepID)
		if err != nil {
			return err
		}
		if rows, _ := stepResult.RowsAffected(); rows != 1 {
			return newStoreError(generated.ErrorCodeStateConflict, "executor-receipt-step", false, nil)
		}
		if _, err := transaction.ExecContext(ctx, `UPDATE plan_runs SET canonical_bytes=?,updated_at=? WHERE run_id=? AND status='running'`, runBytes, run.UpdatedAt, run.RunID); err != nil {
			return err
		}
		_, err = transaction.ExecContext(ctx, `INSERT INTO run_detail_events(run_id,event_type,event_digest,occurred_at) VALUES(?,?,?,?)`, run.RunID, "run.external-receipt-recorded", runFingerprint(run), run.UpdatedAt)
		return err
	})
	if err != nil {
		return generated.ExecutionReceipt{}, err
	}
	if !intent.Created {
		return generated.ExecutionReceipt{}, newStoreError(generated.ErrorCodeStateConflict, "executor-receipt-replay", false, nil)
	}
	return receipt, nil
}

func (repository *ExecutorLeaseRepository) Get(ctx context.Context, leaseID string) (generated.ExecutorLease, error) {
	if repository == nil || repository.store == nil || !validRunToken(leaseID) {
		return generated.ExecutorLease{}, newStoreError(generated.ErrorCodeInputInvalid, "executor-lease", false, nil)
	}
	var canonical []byte
	var status string
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT canonical_bytes,status FROM target_execution_leases WHERE lease_id=? AND lease_kind='external'`, leaseID).Scan(&canonical, &status)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return generated.ExecutorLease{}, newStoreError(generated.ErrorCodeResourceNotFound, "executor-lease", false, nil)
	}
	if err != nil {
		return generated.ExecutorLease{}, err
	}
	lease, err := decodeStoredExecutorLease(canonical)
	if err != nil {
		return generated.ExecutorLease{}, err
	}
	if lease.Status != status {
		return generated.ExecutorLease{}, newStoreError(generated.ErrorCodeIntegrityFailure, "executor-lease-status", false, nil)
	}
	return lease, nil
}

func readExecutorLeaseInTx(ctx context.Context, transaction *sql.Tx, leaseID string) (generated.ExecutorLease, string, int64, error) {
	var canonical []byte
	var status string
	var renewalCount int64
	if err := transaction.QueryRowContext(ctx, `SELECT canonical_bytes,status,renewal_count FROM target_execution_leases WHERE lease_id=? AND lease_kind='external'`, leaseID).Scan(&canonical, &status, &renewalCount); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return generated.ExecutorLease{}, "", 0, newStoreError(generated.ErrorCodeResourceNotFound, "executor-lease", false, err)
		}
		return generated.ExecutorLease{}, "", 0, err
	}
	lease, err := decodeStoredExecutorLease(canonical)
	if err == nil && lease.Status != status {
		err = newStoreError(generated.ErrorCodeIntegrityFailure, "executor-lease-status", false, nil)
	}
	return lease, status, renewalCount, err
}

func decodeStoredExecutorLease(canonical []byte) (generated.ExecutorLease, error) {
	var lease generated.ExecutorLease
	if json.Unmarshal(canonical, &lease) != nil || !validStoredExecutorLease(lease) {
		return generated.ExecutorLease{}, newStoreError(generated.ErrorCodeIntegrityFailure, "executor-lease", false, nil)
	}
	reencoded, _ := json.Marshal(lease)
	if string(reencoded) != string(canonical) {
		return generated.ExecutorLease{}, newStoreError(generated.ErrorCodeIntegrityFailure, "executor-lease", false, nil)
	}
	return lease, nil
}

func validStoredExecutorLease(lease generated.ExecutorLease) bool {
	raw, err := json.Marshal(lease)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDExecutorLease, raw, generated.ContractExact) != nil {
		return false
	}
	claimed, err := time.Parse(time.RFC3339, lease.ClaimedAt)
	if err != nil {
		return false
	}
	renewAfter, expiry, err := executorLeaseTimes(lease)
	if err != nil {
		return false
	}
	maximum, err := time.Parse(time.RFC3339, lease.MaximumExpiresAt)
	return err == nil && expiry.Equal(claimed.Add(time.Duration(generated.ExecutorLeaseSeconds)*time.Second)) && maximum.Equal(expiry) && renewAfter.After(claimed) && !renewAfter.After(expiry)
}

func executorLeaseTimes(lease generated.ExecutorLease) (time.Time, time.Time, error) {
	renewAfter, renewErr := time.Parse(time.RFC3339, lease.RenewAfter)
	expiresAt, expiryErr := time.Parse(time.RFC3339, lease.LeaseExpiresAt)
	if renewErr != nil || expiryErr != nil {
		return time.Time{}, time.Time{}, newStoreError(generated.ErrorCodeIntegrityFailure, "executor-lease-time", false, errors.Join(renewErr, expiryErr))
	}
	return renewAfter, expiresAt, nil
}

func validExecutorClaim(request generated.ExecutorClaimRequest) bool {
	raw, err := json.Marshal(request)
	return err == nil && generated.ValidateContractJSON(generated.SchemaIDExecutorClaimRequest, raw, generated.ContractExact) == nil
}

func validExecutorRenewal(request generated.ExecutorRenewRequest) bool {
	raw, err := json.Marshal(request)
	return err == nil && generated.ValidateContractJSON(generated.SchemaIDExecutorRenewRequest, raw, generated.ContractExact) == nil
}

func validExecutionReceiptRequest(request generated.ExecutionReceiptRequest) bool {
	raw, err := json.Marshal(request)
	return err == nil && generated.ValidateContractJSON(generated.SchemaIDExecutionReceiptRequest, raw, generated.ContractExact) == nil
}

func validUTCSecond(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Equal(value.Truncate(time.Second))
}
