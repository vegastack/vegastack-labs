package store

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

// OffsiteCleanupObligation is the secret-free authority needed to retry the
// exact provider cleanup after a process restart. It never stores credential
// material; the reference and fingerprint must be borrowed again.
type OffsiteCleanupObligation struct {
	ObligationID, GenerationID, ObjectKey, UploadID string
	CredentialReferenceID, CredentialFingerprint    string
	PlanID, PlanDigest, RunID, StepID, LeaseID      string
	SourceRevision, StateRevision, RecoveryEpoch    int64
	CreatedAt                                       time.Time
}

func (repository *OffsiteRepository) AppendCleanupObligation(ctx context.Context, record OffsiteCleanupObligation) error {
	if repository == nil || repository.backup == nil || repository.backup.store == nil || record.ObligationID == "" || record.GenerationID == "" || record.ObjectKey == "" || record.UploadID == "" || record.CredentialReferenceID == "" || len(record.CredentialFingerprint) != 71 || !strings.HasPrefix(record.CredentialFingerprint, "sha256:") || record.PlanID == "" || record.PlanDigest == "" || record.RunID == "" || record.StepID == "" || record.LeaseID == "" || record.SourceRevision < 0 || record.StateRevision < 0 || record.RecoveryEpoch < 0 {
		return newStoreError(generated.ErrorCodeInputInvalid, "offsite-cleanup-obligation", false, nil)
	}
	record.CreatedAt = repository.backup.store.config.Clock().UTC().Truncate(time.Second)
	return repository.inCustodyTx(ctx, func(ctx context.Context, transaction *sql.Tx) error {
		var count int
		if err := transaction.QueryRowContext(ctx, `SELECT COUNT(1) FROM backup_offsite_run_specs s JOIN backup_offsite_execution_leases l ON l.generation_id=s.generation_id WHERE s.generation_id=? AND s.parent_reference_id=? AND s.source_revision=? AND s.state_revision=? AND s.recovery_epoch=? AND l.lease_id=? AND l.plan_id=? AND l.plan_digest=? AND l.run_id=? AND l.step_id=? AND l.source_revision=? AND l.state_revision=? AND l.recovery_epoch=?`,
			record.GenerationID, record.CredentialReferenceID, record.SourceRevision, record.StateRevision, record.RecoveryEpoch, record.LeaseID, record.PlanID, record.PlanDigest, record.RunID, record.StepID, record.SourceRevision, record.StateRevision, record.RecoveryEpoch).Scan(&count); err != nil {
			return backupWriteError(err)
		}
		if count != 1 {
			return newStoreError(generated.ErrorCodePlanStale, "offsite-cleanup-obligation", false, nil)
		}
		_, err := transaction.ExecContext(ctx, `INSERT INTO backup_offsite_cleanup_obligations(obligation_id,generation_id,object_key,upload_id,credential_reference_id,credential_fingerprint,plan_id,plan_digest,run_id,step_id,lease_id,source_revision,state_revision,recovery_epoch,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			record.ObligationID, record.GenerationID, record.ObjectKey, record.UploadID, record.CredentialReferenceID, record.CredentialFingerprint, record.PlanID, record.PlanDigest, record.RunID, record.StepID, record.LeaseID, record.SourceRevision, record.StateRevision, record.RecoveryEpoch, record.CreatedAt.Format(time.RFC3339))
		return backupWriteError(err)
	})
}

func (repository *OffsiteRepository) PendingCleanupObligations(ctx context.Context, referenceID, fingerprint string, recoveryEpoch int64) ([]OffsiteCleanupObligation, error) {
	if repository == nil || repository.backup == nil || repository.backup.store == nil || referenceID == "" || fingerprint == "" || recoveryEpoch < 0 {
		return nil, newStoreError(generated.ErrorCodeInputInvalid, "offsite-cleanup-obligation", false, nil)
	}
	result := []OffsiteCleanupObligation{}
	err := repository.backup.store.Read(ctx, func(tx ReadTx) error {
		rows, err := tx.query(ctx, `SELECT o.obligation_id,o.generation_id,o.object_key,o.upload_id,o.credential_reference_id,o.credential_fingerprint,o.plan_id,o.plan_digest,o.run_id,o.step_id,o.lease_id,o.source_revision,o.state_revision,o.recovery_epoch,o.created_at FROM backup_offsite_cleanup_obligations o LEFT JOIN backup_offsite_cleanup_outcomes x ON x.obligation_id=o.obligation_id WHERE x.obligation_id IS NULL AND o.credential_reference_id=? AND o.credential_fingerprint=? AND o.recovery_epoch=? ORDER BY o.created_at,o.obligation_id`, referenceID, fingerprint, recoveryEpoch)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var record OffsiteCleanupObligation
			var created string
			if err := rows.Scan(&record.ObligationID, &record.GenerationID, &record.ObjectKey, &record.UploadID, &record.CredentialReferenceID, &record.CredentialFingerprint, &record.PlanID, &record.PlanDigest, &record.RunID, &record.StepID, &record.LeaseID, &record.SourceRevision, &record.StateRevision, &record.RecoveryEpoch, &created); err != nil {
				return err
			}
			record.CreatedAt, err = time.Parse(time.RFC3339, created)
			if err != nil {
				return err
			}
			result = append(result, record)
		}
		return rows.Err()
	})
	return result, err
}

func (repository *OffsiteRepository) ResolveCleanupObligation(ctx context.Context, obligationID string) error {
	if repository == nil || repository.backup == nil || repository.backup.store == nil || obligationID == "" {
		return newStoreError(generated.ErrorCodeInputInvalid, "offsite-cleanup-obligation", false, nil)
	}
	return repository.inCustodyTx(ctx, func(ctx context.Context, transaction *sql.Tx) error {
		_, err := transaction.ExecContext(ctx, `INSERT INTO backup_offsite_cleanup_outcomes(obligation_id,outcome,resolved_at) VALUES(?,'resolved',?)`, obligationID, repository.backup.store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339))
		return backupWriteError(err)
	})
}
