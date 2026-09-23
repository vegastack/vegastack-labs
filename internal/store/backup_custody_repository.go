package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

// BackupCustodyAttempt is the server-owned write-ahead record for one finite
// repository custodian. It contains authority bindings, never credentials.
type BackupCustodyAttempt struct {
	AttemptID, Role, PlanID, PlanDigest, RunID, StepID string
	LeaseID, RepositoryID, RepositoryClass, PointID    string
	SourceID                                           string
	SourceRevision, RecoveryEpoch                      int64
	MaximumExpiresAt                                   time.Time
	NonceDigest                                        string
}

func (repository *BackupRepository) BeginBackupCustody(ctx context.Context, request BackupCustodyAttempt) error {
	if repository == nil || repository.store == nil || request.AttemptID == "" ||
		(request.Role != "writer" && request.Role != "verifier") || request.PlanID == "" || !validBackupDigest(request.PlanDigest) ||
		request.RunID == "" || request.StepID == "" || request.LeaseID == "" || request.RepositoryID == "" || request.PointID == "" || request.SourceID == "" ||
		(request.RepositoryClass != "standard" && request.RepositoryClass != "critical") || request.SourceRevision < 0 || request.RecoveryEpoch < 0 ||
		request.MaximumExpiresAt.IsZero() || !validBackupDigest(request.NonceDigest) {
		return backupStoreError(generated.ErrorCodeInputInvalid, "backup-custody")
	}
	now := repository.store.config.Clock().UTC().Truncate(time.Second)
	if !now.Before(request.MaximumExpiresAt) {
		return backupStoreError(generated.ErrorCodePlanStale, "backup-custody")
	}
	return repository.inTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var count int
		stamp, expiry := now.Format(time.RFC3339), request.MaximumExpiresAt.UTC().Truncate(time.Second).Format(time.RFC3339)
		if request.Role == "writer" {
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM backup_writer_leases WHERE lease_id=? AND point_id IS NULL AND plan_id=? AND plan_digest=? AND run_id=? AND step_id=? AND repository_id=? AND repository_class=? AND source_revision=? AND recovery_epoch=? AND maximum_expires_at=? AND released_at IS NULL`, request.LeaseID, request.PlanID, request.PlanDigest, request.RunID, request.StepID, request.RepositoryID, request.RepositoryClass, request.SourceRevision, request.RecoveryEpoch, expiry).Scan(&count); err != nil {
				return backupWriteError(err)
			}
		} else if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM backup_read_leases WHERE lease_id=? AND point_id=? AND repository_id=? AND repository_class=? AND source_revision=? AND recovery_epoch=? AND maximum_expires_at=? AND released_at IS NULL`, request.LeaseID, request.PointID, request.RepositoryID, request.RepositoryClass, request.SourceRevision, request.RecoveryEpoch, expiry).Scan(&count); err != nil {
			return backupWriteError(err)
		}
		if count != 1 {
			return backupStoreError(generated.ErrorCodePlanStale, "backup-custody")
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO backup_custody_attempts(attempt_id,role,plan_id,plan_digest,run_id,step_id,lease_id,repository_id,repository_class,point_id,source_id,source_revision,recovery_epoch,maximum_expires_at,nonce_digest,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			request.AttemptID, request.Role, request.PlanID, request.PlanDigest, request.RunID, request.StepID, request.LeaseID, request.RepositoryID, request.RepositoryClass, request.PointID, request.SourceID, request.SourceRevision, request.RecoveryEpoch, expiry, request.NonceDigest, stamp)
		return backupWriteError(err)
	})
}

func (repository *BackupRepository) FinishBackupCustody(ctx context.Context, attemptID, outcome string) error {
	if repository == nil || repository.store == nil || attemptID == "" || (outcome != "succeeded" && outcome != "failed" && outcome != "uncertain") {
		return backupStoreError(generated.ErrorCodeInputInvalid, "backup-custody")
	}
	stamp := repository.store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339)
	return repository.inTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM backup_custody_attempts WHERE attempt_id=?`, attemptID).Scan(&count); err != nil {
			return backupWriteError(err)
		}
		if count != 1 {
			return backupStoreError(generated.ErrorCodeStateConflict, "backup-custody")
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO backup_custody_outcomes(attempt_id,outcome,created_at) VALUES(?,?,?)`, attemptID, outcome, stamp)
		return backupWriteError(err)
	})
}
