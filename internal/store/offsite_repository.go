package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

// OffsiteGenerationRecord is the store's provider-neutral persistence input.
// CanonicalJSON is produced and validated by the backup domain before this
// boundary; it contains only the sanitized generation receipt.
type OffsiteGenerationRecord struct {
	GenerationID, SourcePointID, RepositoryID, SnapshotID string
	CanonicalJSON                                         []byte
	SessionExpiries                                       []time.Time
	SourceRevision, RecoveryEpoch                         int64
	IssuanceStoppedAt                                     time.Time
}

type OffsiteProofRecord struct {
	ProofID, ProofDigest, GenerationID, Status, ProofClass string
	CanonicalJSON                                          []byte
	FullReadAt, ObservedAt                                 time.Time
	RecoveryEpoch                                          int64
}

type OffsiteStatusRecord struct {
	GenerationID, Status, ProofClass, LastGoodProofID string
	SourcePointID, RepositoryID, SnapshotID           string
	RecoveryEpoch                                     int64
}

// OffsiteRepository is append-only storage. Domain validation stays in the
// backup package so store does not create an import cycle.
type OffsiteRepository struct{ backup *BackupRepository }

func NewOffsiteRepository(authority *Store) *OffsiteRepository {
	return &OffsiteRepository{backup: NewBackupRepository(authority)}
}

func (repository *OffsiteRepository) AppendGeneration(ctx context.Context, record OffsiteGenerationRecord) error {
	if repository == nil || repository.backup == nil || repository.backup.store == nil || record.GenerationID == "" || record.SourcePointID == "" || record.RepositoryID == "" || record.SnapshotID == "" || len(record.CanonicalJSON) < 2 || len(record.SessionExpiries) == 0 || record.IssuanceStoppedAt.IsZero() {
		return backupStoreError(generated.ErrorCodeInputInvalid, "offsite-generation")
	}
	createdAt := repository.backup.store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339)
	return repository.backup.inTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var currentEpoch int64
		if err := tx.QueryRowContext(ctx, `SELECT recovery_epoch FROM system_meta WHERE id=1`).Scan(&currentEpoch); err != nil {
			return backupWriteError(err)
		}
		if currentEpoch != record.RecoveryEpoch {
			return backupStoreError(generated.ErrorCodePlanStale, "offsite-generation")
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO backup_offsite_generations(generation_id,source_point_id,repository_id,offsite_snapshot_id,pending_json,source_revision,recovery_epoch,issuance_stopped_at,created_at) VALUES(?,?,?,?,?,?,?,?,?)`,
			record.GenerationID, record.SourcePointID, record.RepositoryID, record.SnapshotID, string(record.CanonicalJSON), record.SourceRevision, record.RecoveryEpoch, record.IssuanceStoppedAt.UTC().Format(time.RFC3339Nano), createdAt); err != nil {
			return backupWriteError(err)
		}
		for index, expiry := range record.SessionExpiries {
			if expiry.IsZero() {
				return backupStoreError(generated.ErrorCodeInputInvalid, "offsite-generation-expiry")
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO backup_offsite_session_expiries(generation_id,sequence,expires_at) VALUES(?,?,?)`, record.GenerationID, index+1, expiry.UTC().Format(time.RFC3339Nano)); err != nil {
				return backupWriteError(err)
			}
		}
		return nil
	})
}

func (repository *OffsiteRepository) AppendProof(ctx context.Context, record OffsiteProofRecord) error {
	if repository == nil || repository.backup == nil || repository.backup.store == nil || record.ProofID == "" || record.ProofDigest == "" || record.GenerationID == "" || len(record.CanonicalJSON) < 2 || record.ObservedAt.IsZero() {
		return backupStoreError(generated.ErrorCodeInputInvalid, "offsite-proof")
	}
	createdAt := repository.backup.store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339)
	var fullRead any
	if !record.FullReadAt.IsZero() {
		fullRead = record.FullReadAt.UTC().Format(time.RFC3339Nano)
	}
	return repository.backup.inTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var currentEpoch int64
		if err := tx.QueryRowContext(ctx, `SELECT recovery_epoch FROM system_meta WHERE id=1`).Scan(&currentEpoch); err != nil {
			return backupWriteError(err)
		}
		if currentEpoch != record.RecoveryEpoch {
			return backupStoreError(generated.ErrorCodePlanStale, "offsite-proof")
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO backup_offsite_proofs(proof_id,proof_digest,generation_id,status,proof_class,proof_json,full_read_at,observed_at,recovery_epoch,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`,
			record.ProofID, record.ProofDigest, record.GenerationID, record.Status, record.ProofClass, string(record.CanonicalJSON), fullRead, record.ObservedAt.UTC().Format(time.RFC3339Nano), record.RecoveryEpoch, createdAt)
		return backupWriteError(err)
	})
}

func (repository *OffsiteRepository) AppendLastGood(ctx context.Context, proofID, proofDigest, generationID string, sourceRevision, expectedStateRevision, recoveryEpoch int64) error {
	if repository == nil || repository.backup == nil || repository.backup.store == nil {
		return backupStoreError(generated.ErrorCodeInputInvalid, "offsite-last-good")
	}
	return repository.backup.inTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var stateRevision, currentEpoch int64
		var storedDigest string
		if err := tx.QueryRowContext(ctx, `SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&stateRevision, &currentEpoch); err != nil {
			return backupWriteError(err)
		}
		if stateRevision != expectedStateRevision || currentEpoch != recoveryEpoch {
			return backupStoreError(generated.ErrorCodePlanStale, "offsite-last-good")
		}
		if err := tx.QueryRowContext(ctx, `SELECT proof_digest FROM backup_offsite_proofs WHERE proof_id=? AND generation_id=?`, proofID, generationID).Scan(&storedDigest); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return backupStoreError(generated.ErrorCodePrerequisiteBlocked, "offsite-last-good")
			}
			return backupWriteError(err)
		}
		if storedDigest != proofDigest {
			return backupStoreError(generated.ErrorCodeIntegrityFailure, "offsite-last-good")
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO backup_offsite_last_good_history(proof_id,generation_id,source_revision,recovery_epoch,advanced_at) VALUES(?,?,?,?,?)`,
			proofID, generationID, sourceRevision, recoveryEpoch, repository.backup.store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339))
		return backupWriteError(err)
	})
}

func (repository *OffsiteRepository) GenerationJSON(ctx context.Context, generationID string) ([]byte, error) {
	var body string
	if repository == nil || repository.backup == nil || repository.backup.store == nil || generationID == "" {
		return nil, backupStoreError(generated.ErrorCodeInputInvalid, "offsite-generation")
	}
	err := repository.backup.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT pending_json FROM backup_offsite_generations WHERE generation_id=?`, generationID).Scan(&body)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, backupStoreError(generated.ErrorCodeResourceNotFound, "offsite-generation")
	}
	if err != nil {
		return nil, backupWriteError(err)
	}
	return []byte(body), nil
}

func (repository *OffsiteRepository) Status(ctx context.Context, generationID string) (OffsiteStatusRecord, error) {
	var result OffsiteStatusRecord
	if repository == nil || repository.backup == nil || repository.backup.store == nil || generationID == "" {
		return result, backupStoreError(generated.ErrorCodeInputInvalid, "offsite-status")
	}
	err := repository.backup.store.Read(ctx, func(tx ReadTx) error {
		if err := tx.queryRow(ctx, `SELECT generation_id,source_point_id,repository_id,offsite_snapshot_id,recovery_epoch FROM backup_offsite_generations WHERE generation_id=?`, generationID).
			Scan(&result.GenerationID, &result.SourcePointID, &result.RepositoryID, &result.SnapshotID, &result.RecoveryEpoch); err != nil {
			return err
		}
		result.Status = "pending"
		err := tx.queryRow(ctx, `SELECT status,proof_class FROM backup_offsite_proofs WHERE generation_id=? ORDER BY created_at DESC,proof_id DESC LIMIT 1`, generationID).Scan(&result.Status, &result.ProofClass)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		err = tx.queryRow(ctx, `SELECT proof_id FROM backup_offsite_last_good_history WHERE recovery_epoch=? ORDER BY sequence DESC LIMIT 1`, result.RecoveryEpoch).Scan(&result.LastGoodProofID)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	})
	if errors.Is(err, sql.ErrNoRows) {
		return result, backupStoreError(generated.ErrorCodeResourceNotFound, "offsite-status")
	}
	if err != nil {
		return result, backupWriteError(err)
	}
	return result, nil
}
