package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

type OffsiteCustodyBinding struct {
	AttemptID, PlanID, PlanDigest, RunID, StepID, LeaseID string
	Role                                                  string
	GenerationID, SourcePointID, NonceDigest              string
	StateRevision, RecoveryEpoch                          int64
	MaximumExpiresAt                                      time.Time
}

func (repository *OffsiteRepository) VerifyCustodyLease(ctx context.Context, binding OffsiteCustodyBinding, at time.Time) error {
	if err := repository.verifyTargetCustodyLease(ctx, binding, at); err != nil {
		return err
	}
	var count int
	err := repository.backup.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT COUNT(1) FROM backup_offsite_execution_leases WHERE lease_id=? AND plan_id=? AND plan_digest=? AND run_id=? AND step_id=? AND generation_id=? AND source_point_id=? AND state_revision=? AND recovery_epoch=? AND maximum_expires_at=?`,
			binding.LeaseID, binding.PlanID, binding.PlanDigest, binding.RunID, binding.StepID, binding.GenerationID, binding.SourcePointID, binding.StateRevision, binding.RecoveryEpoch, binding.MaximumExpiresAt.UTC().Format(time.RFC3339)).Scan(&count)
	})
	if err != nil {
		return err
	}
	if count != 1 {
		return newStoreError(generated.ErrorCodePlanStale, "offsite-custody-lease", false, nil)
	}
	return nil
}

func (repository *OffsiteRepository) verifyTargetCustodyLease(ctx context.Context, binding OffsiteCustodyBinding, at time.Time) error {
	if repository == nil || repository.backup.store == nil || at.IsZero() || !at.Before(binding.MaximumExpiresAt) {
		return newStoreError(generated.ErrorCodePlanStale, "offsite-custody-lease", false, nil)
	}
	var count int
	err := repository.backup.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT COUNT(1) FROM target_execution_leases l JOIN plan_runs r ON r.run_id=l.run_id JOIN plan_run_steps s ON s.run_id=l.run_id AND s.step_id=l.step_id
			WHERE l.lease_id=? AND r.plan_id=? AND r.plan_digest=? AND l.run_id=? AND l.step_id=? AND l.target_id=? AND l.recovery_epoch=? AND l.status='active' AND l.maximum_expires_at=?
			AND r.status='running' AND r.state_revision=? AND s.adapter_id='labs.r2-offsite' AND s.operation_type='backup.offsite.copy' AND s.status='running'`,
			binding.LeaseID, binding.PlanID, binding.PlanDigest, binding.RunID, binding.StepID, binding.GenerationID, binding.RecoveryEpoch, binding.MaximumExpiresAt.UTC().Format(time.RFC3339), binding.StateRevision).Scan(&count)
	})
	if err != nil {
		return err
	}
	if count != 1 {
		return newStoreError(generated.ErrorCodePlanStale, "offsite-custody-lease", false, nil)
	}
	return nil
}

func (repository *OffsiteRepository) BindCustodyLease(ctx context.Context, binding OffsiteCustodyBinding) error {
	if err := repository.verifyTargetCustodyLease(ctx, binding, repository.backup.store.config.Clock().UTC()); err != nil {
		return err
	}
	createdAt := repository.backup.store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339)
	return repository.inCustodyTx(ctx, func(ctx context.Context, transaction *sql.Tx) error {
		var count int
		if err := transaction.QueryRowContext(ctx, `SELECT COUNT(1) FROM backup_offsite_execution_leases WHERE lease_id=? AND plan_id=? AND plan_digest=? AND run_id=? AND step_id=? AND generation_id=? AND source_point_id=? AND state_revision=? AND recovery_epoch=? AND maximum_expires_at=?`,
			binding.LeaseID, binding.PlanID, binding.PlanDigest, binding.RunID, binding.StepID, binding.GenerationID, binding.SourcePointID, binding.StateRevision, binding.RecoveryEpoch, binding.MaximumExpiresAt.UTC().Format(time.RFC3339)).Scan(&count); err != nil {
			return err
		}
		if count == 1 {
			return nil
		}
		_, err := transaction.ExecContext(ctx, `INSERT INTO backup_offsite_execution_leases(lease_id,plan_id,plan_digest,run_id,step_id,generation_id,source_point_id,state_revision,recovery_epoch,maximum_expires_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
			binding.LeaseID, binding.PlanID, binding.PlanDigest, binding.RunID, binding.StepID, binding.GenerationID, binding.SourcePointID, binding.StateRevision, binding.RecoveryEpoch, binding.MaximumExpiresAt.UTC().Format(time.RFC3339), createdAt)
		return err
	})
}

func (repository *OffsiteRepository) BeginCustody(ctx context.Context, binding OffsiteCustodyBinding) error {
	if binding.Role != "offsite-writer" && binding.Role != "offsite-verifier" {
		return newStoreError(generated.ErrorCodeInputInvalid, "offsite-custody-role", false, nil)
	}
	if err := repository.VerifyCustodyLease(ctx, binding, repository.backup.store.config.Clock().UTC()); err != nil {
		return err
	}
	createdAt := repository.backup.store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339)
	return repository.inCustodyTx(ctx, func(ctx context.Context, transaction *sql.Tx) error {
		_, err := transaction.ExecContext(ctx, `INSERT INTO backup_offsite_custody_attempts(attempt_id,plan_id,plan_digest,run_id,step_id,lease_id,role,generation_id,source_point_id,state_revision,recovery_epoch,maximum_expires_at,nonce_digest,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			binding.AttemptID, binding.PlanID, binding.PlanDigest, binding.RunID, binding.StepID, binding.LeaseID, binding.Role, binding.GenerationID, binding.SourcePointID, binding.StateRevision, binding.RecoveryEpoch, binding.MaximumExpiresAt.UTC().Format(time.RFC3339), binding.NonceDigest, createdAt)
		return err
	})
}

func (repository *OffsiteRepository) FinishCustody(ctx context.Context, attemptID, outcome string) error {
	if repository == nil || repository.backup.store == nil || attemptID == "" || (outcome != "succeeded" && outcome != "failed" && outcome != "uncertain") {
		return newStoreError(generated.ErrorCodeInputInvalid, "offsite-custody", false, nil)
	}
	return repository.inCustodyTx(ctx, func(ctx context.Context, transaction *sql.Tx) error {
		_, err := transaction.ExecContext(ctx, `INSERT INTO backup_offsite_custody_outcomes(attempt_id,outcome,created_at) VALUES(?,?,?)`, attemptID, outcome, repository.backup.store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339))
		return err
	})
}

func (repository *OffsiteRepository) inCustodyTx(ctx context.Context, business func(context.Context, *sql.Tx) error) error {
	repository.backup.store.mu.Lock()
	defer repository.backup.store.mu.Unlock()
	transaction, err := repository.backup.store.conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	if err := business(ctx, transaction); err != nil {
		return err
	}
	return transaction.Commit()
}
