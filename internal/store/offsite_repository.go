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
	Rules                                                 []OffsiteRuleRecord
	Objects                                               []OffsiteObjectRecord
	SessionExpiries                                       []time.Time
	SourceRevision, StateRevision, RecoveryEpoch          int64
	IssuanceStoppedAt                                     time.Time
}

type OffsiteRunSpecRecord struct {
	GenerationID, SourcePointID, SnapshotPath, RepositoryURL               string
	ParentReferenceID, PasswordReferenceID, RuleDigest, G008EvidenceDigest string
	CanonicalJSON                                                          []byte
	MaximumBytes, MaximumPUTs, MaximumLISTs                                int64
	MaximumRetainedGenerations, RuleLimit                                  int
	RetentionSeconds, SessionTTLSeconds, StateRevision, RecoveryEpoch      int64
}

type OffsiteRuleRecord struct{ RuleID, Prefix string }
type OffsiteObjectRecord struct {
	Key, Digest string
	Bytes       int64
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

func (repository *OffsiteRepository) AppendRunSpec(ctx context.Context, record OffsiteRunSpecRecord) error {
	if repository == nil || repository.backup == nil || repository.backup.store == nil || record.GenerationID == "" || record.SourcePointID == "" || record.SnapshotPath == "" || record.RepositoryURL == "" ||
		record.ParentReferenceID == "" || record.PasswordReferenceID == "" || record.ParentReferenceID == record.PasswordReferenceID || record.RuleDigest == "" || record.G008EvidenceDigest == "" || len(record.CanonicalJSON) < 2 ||
		record.MaximumBytes <= 0 || record.MaximumPUTs <= 0 || record.MaximumLISTs <= 0 || record.MaximumRetainedGenerations <= 0 || record.RuleLimit <= 0 || record.RetentionSeconds <= 0 || record.SessionTTLSeconds <= 0 || record.SessionTTLSeconds > 900 || record.StateRevision < 0 || record.RecoveryEpoch < 0 {
		return backupStoreError(generated.ErrorCodeInputInvalid, "offsite-run-spec")
	}
	createdAt := repository.backup.store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339)
	return repository.backup.inTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var stateRevision, recoveryEpoch int64
		if err := tx.QueryRowContext(ctx, `SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&stateRevision, &recoveryEpoch); err != nil {
			return backupWriteError(err)
		}
		if stateRevision != record.StateRevision || recoveryEpoch != record.RecoveryEpoch {
			return backupStoreError(generated.ErrorCodePlanStale, "offsite-run-spec")
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO backup_offsite_run_specs(generation_id,source_point_id,snapshot_path,repository_url,parent_reference_id,password_reference_id,rule_digest,g008_evidence_digest,maximum_bytes,maximum_puts,maximum_lists,maximum_retained_generations,rule_limit,retention_seconds,session_ttl_seconds,canonical_json,state_revision,recovery_epoch,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			record.GenerationID, record.SourcePointID, record.SnapshotPath, record.RepositoryURL, record.ParentReferenceID, record.PasswordReferenceID, record.RuleDigest, record.G008EvidenceDigest, record.MaximumBytes, record.MaximumPUTs, record.MaximumLISTs, record.MaximumRetainedGenerations, record.RuleLimit, record.RetentionSeconds, record.SessionTTLSeconds, string(record.CanonicalJSON), record.StateRevision, record.RecoveryEpoch, createdAt)
		return backupWriteError(err)
	})
}

func (repository *OffsiteRepository) RunSpec(ctx context.Context, generationID string) (OffsiteRunSpecRecord, error) {
	var record OffsiteRunSpecRecord
	var canonical string
	if repository == nil || repository.backup == nil || repository.backup.store == nil || generationID == "" {
		return record, backupStoreError(generated.ErrorCodeInputInvalid, "offsite-run-spec")
	}
	err := repository.backup.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT generation_id,source_point_id,snapshot_path,repository_url,parent_reference_id,password_reference_id,rule_digest,g008_evidence_digest,maximum_bytes,maximum_puts,maximum_lists,maximum_retained_generations,rule_limit,retention_seconds,session_ttl_seconds,canonical_json,state_revision,recovery_epoch FROM backup_offsite_run_specs WHERE generation_id=?`, generationID).
			Scan(&record.GenerationID, &record.SourcePointID, &record.SnapshotPath, &record.RepositoryURL, &record.ParentReferenceID, &record.PasswordReferenceID, &record.RuleDigest, &record.G008EvidenceDigest, &record.MaximumBytes, &record.MaximumPUTs, &record.MaximumLISTs, &record.MaximumRetainedGenerations, &record.RuleLimit, &record.RetentionSeconds, &record.SessionTTLSeconds, &canonical, &record.StateRevision, &record.RecoveryEpoch)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return record, backupStoreError(generated.ErrorCodeResourceNotFound, "offsite-run-spec")
	}
	if err != nil {
		return record, backupWriteError(err)
	}
	record.CanonicalJSON = []byte(canonical)
	return record, nil
}

func (repository *OffsiteRepository) AppendGeneration(ctx context.Context, record OffsiteGenerationRecord) error {
	if repository == nil || repository.backup == nil || repository.backup.store == nil || record.GenerationID == "" || record.SourcePointID == "" || record.RepositoryID == "" || record.SnapshotID == "" || len(record.CanonicalJSON) < 2 || len(record.Rules) != 5 || len(record.Objects) == 0 || len(record.SessionExpiries) == 0 || record.IssuanceStoppedAt.IsZero() {
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
		if _, err := tx.ExecContext(ctx, `INSERT INTO backup_offsite_generations(generation_id,source_point_id,repository_id,offsite_snapshot_id,pending_json,source_revision,state_revision,recovery_epoch,issuance_stopped_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`,
			record.GenerationID, record.SourcePointID, record.RepositoryID, record.SnapshotID, string(record.CanonicalJSON), record.SourceRevision, record.StateRevision, record.RecoveryEpoch, record.IssuanceStoppedAt.UTC().Format(time.RFC3339Nano), createdAt); err != nil {
			return backupWriteError(err)
		}
		for index, rule := range record.Rules {
			if _, err := tx.ExecContext(ctx, `INSERT INTO backup_offsite_retention_rules(generation_id,sequence,rule_id,protected_prefix) VALUES(?,?,?,?)`, record.GenerationID, index+1, rule.RuleID, rule.Prefix); err != nil {
				return backupWriteError(err)
			}
		}
		for index, object := range record.Objects {
			if _, err := tx.ExecContext(ctx, `INSERT INTO backup_offsite_objects(generation_id,sequence,object_key,object_digest,object_bytes) VALUES(?,?,?,?,?)`, record.GenerationID, index+1, object.Key, object.Digest, object.Bytes); err != nil {
				return backupWriteError(err)
			}
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

func (repository *OffsiteRepository) AppendLastGood(ctx context.Context, proofID, proofDigest, generationID string, sourceRevision, stateRevision, recoveryEpoch int64) error {
	if repository == nil || repository.backup == nil || repository.backup.store == nil {
		return backupStoreError(generated.ErrorCodeInputInvalid, "offsite-last-good")
	}
	return repository.backup.inTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var currentStateRevision, currentEpoch int64
		var storedDigest string
		if err := tx.QueryRowContext(ctx, `SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&currentStateRevision, &currentEpoch); err != nil {
			return backupWriteError(err)
		}
		if currentStateRevision != stateRevision || currentEpoch != recoveryEpoch {
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
		_, err := tx.ExecContext(ctx, `INSERT INTO backup_offsite_last_good_history(proof_id,generation_id,source_revision,state_revision,recovery_epoch,advanced_at) VALUES(?,?,?,?,?,?)`,
			proofID, generationID, sourceRevision, stateRevision, recoveryEpoch, repository.backup.store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339))
		return backupWriteError(err)
	})
}

func (repository *OffsiteRepository) ProofExists(ctx context.Context, generationID, proofDigest string) (bool, error) {
	if repository == nil || repository.backup == nil || repository.backup.store == nil || generationID == "" || proofDigest == "" {
		return false, backupStoreError(generated.ErrorCodeInputInvalid, "offsite-proof")
	}
	var count int
	err := repository.backup.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT COUNT(*) FROM backup_offsite_proofs WHERE generation_id=? AND proof_digest=?`, generationID, proofDigest).Scan(&count)
	})
	return count == 1, err
}

func (repository *OffsiteRepository) Generation(ctx context.Context, generationID string) (OffsiteGenerationRecord, error) {
	var result OffsiteGenerationRecord
	var body, stopped string
	if repository == nil || repository.backup == nil || repository.backup.store == nil || generationID == "" {
		return result, backupStoreError(generated.ErrorCodeInputInvalid, "offsite-generation")
	}
	err := repository.backup.store.Read(ctx, func(tx ReadTx) error {
		if err := tx.queryRow(ctx, `SELECT generation_id,source_point_id,repository_id,offsite_snapshot_id,pending_json,source_revision,state_revision,recovery_epoch,issuance_stopped_at FROM backup_offsite_generations WHERE generation_id=?`, generationID).
			Scan(&result.GenerationID, &result.SourcePointID, &result.RepositoryID, &result.SnapshotID, &body, &result.SourceRevision, &result.StateRevision, &result.RecoveryEpoch, &stopped); err != nil {
			return err
		}
		parsed, err := time.Parse(time.RFC3339Nano, stopped)
		if err != nil {
			return err
		}
		result.IssuanceStoppedAt, result.CanonicalJSON = parsed, []byte(body)
		rules, err := tx.query(ctx, `SELECT rule_id,protected_prefix FROM backup_offsite_retention_rules WHERE generation_id=? ORDER BY sequence`, generationID)
		if err != nil {
			return err
		}
		for rules.Next() {
			var item OffsiteRuleRecord
			if err := rules.Scan(&item.RuleID, &item.Prefix); err != nil {
				rules.Close()
				return err
			}
			result.Rules = append(result.Rules, item)
		}
		if err := rules.Err(); err != nil {
			rules.Close()
			return err
		}
		rules.Close()
		objects, err := tx.query(ctx, `SELECT object_key,object_digest,object_bytes FROM backup_offsite_objects WHERE generation_id=? ORDER BY sequence`, generationID)
		if err != nil {
			return err
		}
		for objects.Next() {
			var item OffsiteObjectRecord
			if err := objects.Scan(&item.Key, &item.Digest, &item.Bytes); err != nil {
				objects.Close()
				return err
			}
			result.Objects = append(result.Objects, item)
		}
		if err := objects.Err(); err != nil {
			objects.Close()
			return err
		}
		objects.Close()
		expiries, err := tx.query(ctx, `SELECT expires_at FROM backup_offsite_session_expiries WHERE generation_id=? ORDER BY sequence`, generationID)
		if err != nil {
			return err
		}
		for expiries.Next() {
			var raw string
			if err := expiries.Scan(&raw); err != nil {
				expiries.Close()
				return err
			}
			parsed, err := time.Parse(time.RFC3339Nano, raw)
			if err != nil {
				expiries.Close()
				return err
			}
			result.SessionExpiries = append(result.SessionExpiries, parsed)
		}
		if err := expiries.Err(); err != nil {
			expiries.Close()
			return err
		}
		return expiries.Close()
	})
	if errors.Is(err, sql.ErrNoRows) {
		return result, backupStoreError(generated.ErrorCodeResourceNotFound, "offsite-generation")
	}
	if err != nil {
		return result, backupWriteError(err)
	}
	return result, nil
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
		err = tx.queryRow(ctx, `SELECT proof_id FROM backup_offsite_last_good_history WHERE generation_id=? AND recovery_epoch=? ORDER BY sequence DESC LIMIT 1`, result.GenerationID, result.RecoveryEpoch).Scan(&result.LastGoodProofID)
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
