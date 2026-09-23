package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

// VerifiedCriticalOffsiteSource is an exact durable local source for one
// off-site generation. It contains no repository password or provider token.
type VerifiedCriticalOffsiteSource struct {
	PendingRecoveryPoint
	VerificationID, VerificationDigest, ProofStatus, ProofClass string
	StateRevision                                               int64
	CreatedAt, VerifiedAt                                       time.Time
	FullReadValidUntil, FunctionalValidUntil                    time.Time
}

// CurrentOffsiteLastGood identifies one exact append-only generation and proof
// selected by the newest current-revision last-good record for a source point.
// Canonical payloads are returned for domain-level revalidation by backup.
type CurrentOffsiteLastGood struct {
	PointID, GenerationID, ProofID, ProofDigest, Status, ProofClass string
	GenerationJSON, ProofJSON                                       []byte
	SourceRevision, StateRevision, RecoveryEpoch                    int64
	CurrentStateRevision, CurrentRecoveryEpoch                      int64
	FullReadAt, ObservedAt                                          time.Time
}

func (repository *OffsiteRepository) CurrentLastGoodForPoint(ctx context.Context, pointID string) (CurrentOffsiteLastGood, error) {
	var result CurrentOffsiteLastGood
	if repository == nil || repository.backup == nil || repository.backup.store == nil || pointID == "" {
		return result, backupStoreError(generated.ErrorCodeInputInvalid, "restore-offsite-last-good")
	}
	var generationJSON, proofJSON, fullRead, observed string
	err := repository.backup.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT g.source_point_id,g.generation_id,h.proof_id,p.proof_digest,p.status,p.proof_class,g.pending_json,p.proof_json,
			h.source_revision,h.state_revision,h.recovery_epoch,m.state_revision,m.recovery_epoch,p.full_read_at,p.observed_at
			FROM backup_offsite_last_good_history h
			JOIN backup_offsite_generations g ON g.generation_id=h.generation_id AND g.source_revision=h.source_revision AND g.recovery_epoch=h.recovery_epoch
			JOIN backup_offsite_proofs p ON p.proof_id=h.proof_id AND p.generation_id=h.generation_id AND p.recovery_epoch=h.recovery_epoch
			CROSS JOIN system_meta m
			WHERE g.source_point_id=? AND m.id=1
			ORDER BY h.sequence DESC LIMIT 1`, pointID).Scan(&result.PointID, &result.GenerationID, &result.ProofID, &result.ProofDigest, &result.Status, &result.ProofClass,
			&generationJSON, &proofJSON, &result.SourceRevision, &result.StateRevision, &result.RecoveryEpoch, &result.CurrentStateRevision, &result.CurrentRecoveryEpoch, &fullRead, &observed)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return result, backupStoreError(generated.ErrorCodePrerequisiteBlocked, "restore-offsite-last-good")
	}
	if err != nil {
		return result, err
	}
	result.FullReadAt, err = time.Parse(time.RFC3339Nano, fullRead)
	if err != nil {
		return CurrentOffsiteLastGood{}, backupStoreError(generated.ErrorCodeIntegrityFailure, "restore-offsite-last-good")
	}
	result.ObservedAt, err = time.Parse(time.RFC3339Nano, observed)
	if err != nil {
		return CurrentOffsiteLastGood{}, backupStoreError(generated.ErrorCodeIntegrityFailure, "restore-offsite-last-good")
	}
	result.GenerationJSON, result.ProofJSON = []byte(generationJSON), []byte(proofJSON)
	return result, nil
}

// GetVerifiedCriticalOffsiteSource fails closed unless the local point and its
// newest proof are live, critical, current-revision/current-epoch, and inside
// both verification cadence windows.
func (repository *BackupRepository) GetVerifiedCriticalOffsiteSource(ctx context.Context, pointID string) (VerifiedCriticalOffsiteSource, error) {
	var result VerifiedCriticalOffsiteSource
	if repository == nil || repository.store == nil || pointID == "" {
		return result, backupStoreError(generated.ErrorCodeInputInvalid, "backup-offsite-source")
	}
	var createdAtText, verifiedAtText, fullAtText, functionalAtText, manifestJSON, policyJSON string
	var currentRevision, currentEpoch int64
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT p.point_id,p.job_id,p.policy_id,p.policy_digest,p.repository_id,p.repository_class,p.manifest_digest,p.manifest_json,p.content_digest,p.inventory_digest,p.source_revision,p.recovery_epoch,
			v.verification_id,v.proof_digest,v.status,v.proof_class,v.state_revision,p.created_at,v.created_at,v.full_read_at,v.functional_restored_at,d.canonical_json,m.state_revision,m.recovery_epoch
			FROM recovery_points p
			JOIN backup_local_verifications v ON v.point_id=p.point_id
			JOIN backup_policy_drafts d ON d.policy_digest=p.policy_digest AND d.recovery_epoch=p.recovery_epoch
			CROSS JOIN system_meta m
			WHERE p.point_id=? AND m.id=1 ORDER BY v.created_at DESC,v.verification_id DESC LIMIT 1`, pointID).Scan(
			&result.PointID, &result.JobID, &result.PolicyID, &result.PolicyDigest, &result.RepositoryID, &result.RepositoryClass, &result.ManifestDigest, &manifestJSON,
			&result.ContentDigest, &result.InventoryDigest, &result.SourceRevision, &result.RecoveryEpoch, &result.VerificationID, &result.VerificationDigest,
			&result.ProofStatus, &result.ProofClass, &result.StateRevision, &createdAtText, &verifiedAtText, &fullAtText, &functionalAtText, &policyJSON, &currentRevision, &currentEpoch)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return result, backupStoreError(generated.ErrorCodeResourceNotFound, "backup-offsite-source")
	}
	if err != nil {
		return result, err
	}
	var policy generated.BackupPolicy
	createdAt, createdErr := time.Parse(time.RFC3339, createdAtText)
	verifiedAt, verifiedErr := time.Parse(time.RFC3339, verifiedAtText)
	fullAt, fullErr := time.Parse(time.RFC3339, fullAtText)
	functionalAt, functionalErr := time.Parse(time.RFC3339, functionalAtText)
	now := repository.store.config.Clock().UTC()
	if result.RepositoryClass != "critical" || result.ProofStatus != "local-verified" || result.ProofClass != "live" ||
		result.StateRevision != currentRevision || result.RecoveryEpoch != currentEpoch || createdErr != nil || verifiedErr != nil || fullErr != nil || functionalErr != nil ||
		json.Unmarshal([]byte(policyJSON), &policy) != nil || policy.FullPayloadIntervalHours < 1 || policy.FunctionalTestIntervalHours < 1 {
		return VerifiedCriticalOffsiteSource{}, backupStoreError(generated.ErrorCodePrerequisiteBlocked, "backup-offsite-source")
	}
	result.FullReadValidUntil = fullAt.Add(time.Duration(policy.FullPayloadIntervalHours) * time.Hour)
	result.FunctionalValidUntil = functionalAt.Add(time.Duration(policy.FunctionalTestIntervalHours) * time.Hour)
	result.CreatedAt, result.VerifiedAt = createdAt, verifiedAt
	if !now.Before(result.FullReadValidUntil) || !now.Before(result.FunctionalValidUntil) {
		return VerifiedCriticalOffsiteSource{}, backupStoreError(generated.ErrorCodePrerequisiteBlocked, "backup-offsite-source-cadence")
	}
	pending, err := repository.GetPendingRecoveryPoint(ctx, pointID)
	if err != nil {
		return VerifiedCriticalOffsiteSource{}, err
	}
	result.PendingRecoveryPoint = pending
	if string(result.ManifestJSON) != manifestJSON {
		return VerifiedCriticalOffsiteSource{}, backupStoreError(generated.ErrorCodeIntegrityFailure, "backup-offsite-source-manifest")
	}
	return result, nil
}
