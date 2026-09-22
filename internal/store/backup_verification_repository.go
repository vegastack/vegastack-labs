package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

// BackupReadLeaseRequest binds one non-destructive verifier to one pending
// point, current state and physical repository root. It excludes writers.
type BackupReadLeaseRequest struct {
	LeaseID, PointID, RepositoryID, RepositoryClass string
	SourceRevision                                  int64
	Expected                                        RevisionToken
	MaximumExpiresAt                                time.Time
}

func (repository *BackupRepository) AcquireBackupReadLease(ctx context.Context, request BackupReadLeaseRequest) error {
	if repository == nil || repository.store == nil || request.LeaseID == "" || request.PointID == "" || request.RepositoryID == "" ||
		(request.RepositoryClass != "standard" && request.RepositoryClass != "critical") || request.SourceRevision < 0 ||
		request.Expected.StateRevision < 0 || request.Expected.RecoveryEpoch < 0 || request.MaximumExpiresAt.IsZero() {
		return backupStoreError(generated.ErrorCodeInputInvalid, "backup-read-lease")
	}
	now := repository.store.config.Clock().UTC().Truncate(time.Second)
	if !now.Before(request.MaximumExpiresAt) {
		return backupStoreError(generated.ErrorCodeInputInvalid, "backup-read-lease")
	}
	return repository.inTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var revision, epoch int64
		if err := tx.QueryRowContext(ctx, `SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&revision, &epoch); err != nil {
			return backupWriteError(err)
		}
		if revision != request.Expected.StateRevision || epoch != request.Expected.RecoveryEpoch {
			return backupStoreError(generated.ErrorCodePlanStale, "backup-read-lease")
		}
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM recovery_points WHERE point_id=? AND repository_id=? AND repository_class=? AND source_revision=? AND recovery_epoch=? AND verification_status='pending'`, request.PointID, request.RepositoryID, request.RepositoryClass, request.SourceRevision, epoch).Scan(&count); err != nil {
			return backupWriteError(err)
		}
		if count != 1 {
			return backupStoreError(generated.ErrorCodePlanStale, "backup-read-lease")
		}
		stamp := now.Format(time.RFC3339)
		if _, err := tx.ExecContext(ctx, `UPDATE backup_read_leases SET released_at=? WHERE repository_class=? AND released_at IS NULL AND maximum_expires_at<=?`, stamp, request.RepositoryClass, stamp); err != nil {
			return backupWriteError(err)
		}
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM backup_writer_leases WHERE repository_class=? AND released_at IS NULL AND maximum_expires_at>?`, request.RepositoryClass, stamp).Scan(&count); err != nil {
			return backupWriteError(err)
		}
		if count != 0 {
			return backupStoreError(generated.ErrorCodeStateConflict, "backup-read-lease")
		}
		// A retirement may have changed pack inodes even when its deadline
		// passed. Readers wait for an explicit, reconciled release.
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM backup_retirement_leases WHERE repository_class=? AND released_at IS NULL`, request.RepositoryClass).Scan(&count); err != nil {
			return backupWriteError(err)
		}
		if count != 0 {
			return backupStoreError(generated.ErrorCodeStateConflict, "backup-read-lease")
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO backup_read_leases(lease_id,point_id,repository_id,repository_class,source_revision,state_revision,recovery_epoch,maximum_expires_at,acquired_at,released_at) VALUES(?,?,?,?,?,?,?,?,?,NULL)`, request.LeaseID, request.PointID, request.RepositoryID, request.RepositoryClass, request.SourceRevision, revision, epoch, request.MaximumExpiresAt.UTC().Truncate(time.Second).Format(time.RFC3339), stamp)
		return backupWriteError(err)
	})
}

// VerifyActiveReadLease is called for every guarded REST request. It also
// rechecks current state/epoch so a stale verifier loses access immediately.
func (repository *BackupRepository) VerifyActiveReadLease(ctx context.Context, request BackupReadLeaseRequest, now time.Time) error {
	if repository == nil || repository.store == nil {
		return backupStoreError(generated.ErrorCodeInputInvalid, "backup-read-lease")
	}
	var expires string
	var revision, epoch int64
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT l.maximum_expires_at,m.state_revision,m.recovery_epoch FROM backup_read_leases l CROSS JOIN system_meta m WHERE m.id=1 AND l.lease_id=? AND l.point_id=? AND l.repository_id=? AND l.repository_class=? AND l.source_revision=? AND l.state_revision=? AND l.recovery_epoch=? AND l.released_at IS NULL`, request.LeaseID, request.PointID, request.RepositoryID, request.RepositoryClass, request.SourceRevision, request.Expected.StateRevision, request.Expected.RecoveryEpoch).Scan(&expires, &revision, &epoch)
	})
	if errors.Is(err, sql.ErrNoRows) || revision != request.Expected.StateRevision || epoch != request.Expected.RecoveryEpoch {
		return backupStoreError(generated.ErrorCodePlanStale, "backup-read-lease")
	}
	if err != nil {
		return err
	}
	deadline, err := time.Parse(time.RFC3339, expires)
	if err != nil || !now.Before(deadline) {
		return backupStoreError(generated.ErrorCodePlanStale, "backup-read-lease")
	}
	return nil
}

func (repository *BackupRepository) ReleaseBackupReadLease(ctx context.Context, leaseID string) error {
	if repository == nil || repository.store == nil || leaseID == "" {
		return backupStoreError(generated.ErrorCodeInputInvalid, "backup-read-lease")
	}
	stamp := repository.store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339)
	return repository.inTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `UPDATE backup_read_leases SET released_at=? WHERE lease_id=? AND released_at IS NULL`, stamp, leaseID)
		if err != nil {
			return backupWriteError(err)
		}
		changed, err := result.RowsAffected()
		if err != nil {
			return backupWriteError(err)
		}
		if changed != 1 {
			return backupStoreError(generated.ErrorCodeStateConflict, "backup-read-lease")
		}
		return nil
	})
}

type LocalVerificationRequest struct {
	VerificationID, RunID, PointID, ReadLeaseID                    string
	ManifestDigest, InventoryDigest, ObservedDigest                string
	ContentDigest, CatalogDigest, DependencyDigest, KeyReferenceID string
	SourceRevision                                                 int64
	Expected                                                       RevisionToken
	ProofClass                                                     string // fixture or live; fixture can never advance last-good
	Result                                                         string // passed, failed or uncertain
	ReasonCode                                                     string
	FullReadAt, FunctionalRestoredAt                               time.Time
}

type LocalVerificationReceipt struct {
	VerificationID, ProofDigest, PointID, RepositoryClass, Status, ProofClass string
	ManifestDigest, InventoryDigest                                           string
	StateRevision, RecoveryEpoch                                              int64
}

// AppendLocalVerification records an immutable result. A passed fixture stays
// fixture-only; only the exact central verifier can provide a live proof after
// both full-read and isolated functional restore.
func (repository *BackupRepository) AppendLocalVerification(ctx context.Context, request LocalVerificationRequest) (LocalVerificationReceipt, error) {
	var receipt LocalVerificationReceipt
	if repository == nil || repository.store == nil || request.VerificationID == "" || request.RunID == "" || request.PointID == "" || request.ReadLeaseID == "" ||
		(request.ProofClass != "fixture" && request.ProofClass != "live") ||
		(request.Result != "passed" && request.Result != "failed" && request.Result != "uncertain") ||
		request.Expected.StateRevision < 0 || request.Expected.RecoveryEpoch < 0 || request.SourceRevision < 0 {
		return receipt, backupStoreError(generated.ErrorCodeInputInvalid, "backup-local-verification")
	}
	for _, digest := range []string{request.ManifestDigest, request.InventoryDigest, request.ObservedDigest, request.ContentDigest, request.CatalogDigest, request.DependencyDigest} {
		if !validBackupDigest(digest) {
			return receipt, backupStoreError(generated.ErrorCodeInputInvalid, "backup-local-verification")
		}
	}
	if request.KeyReferenceID == "" {
		return receipt, backupStoreError(generated.ErrorCodeInputInvalid, "backup-local-verification")
	}
	status := request.Result
	if status == "passed" {
		if request.ObservedDigest != request.InventoryDigest || request.FullReadAt.IsZero() || request.FunctionalRestoredAt.IsZero() ||
			request.FullReadAt.After(request.FunctionalRestoredAt) {
			return receipt, backupStoreError(generated.ErrorCodeIntegrityFailure, "backup-local-verification")
		}
		if request.ProofClass == "fixture" {
			status = "fixture-only"
		} else {
			status = "local-verified"
		}
	} else if request.ReasonCode == "" {
		return receipt, backupStoreError(generated.ErrorCodeInputInvalid, "backup-local-verification")
	}
	created := repository.store.config.Clock().UTC()
	if status == "fixture-only" || status == "local-verified" {
		if request.FullReadAt.After(created) || request.FunctionalRestoredAt.After(created) {
			return receipt, backupStoreError(generated.ErrorCodeIntegrityFailure, "backup-local-verification")
		}
	}
	formatOptional := func(value time.Time) any {
		if value.IsZero() {
			return nil
		}
		return value.UTC().Format(time.RFC3339)
	}
	proofBytes, err := json.Marshal(request)
	if err != nil {
		return receipt, backupStoreError(generated.ErrorCodeInputInvalid, "backup-local-verification")
	}
	proofSum := sha256.Sum256(proofBytes)
	proofDigest := "sha256:" + hex.EncodeToString(proofSum[:])
	err = repository.inTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var class, manifestDigest, inventoryDigest, contentDigest, manifestJSON, policyDigest string
		var sourceRevision, pointEpoch, stateRevision, currentEpoch int64
		if err := tx.QueryRowContext(ctx, `SELECT p.repository_class,p.manifest_digest,p.inventory_digest,p.content_digest,p.manifest_json,p.policy_digest,p.source_revision,p.recovery_epoch,m.state_revision,m.recovery_epoch FROM recovery_points p CROSS JOIN system_meta m WHERE p.point_id=? AND m.id=1`, request.PointID).Scan(&class, &manifestDigest, &inventoryDigest, &contentDigest, &manifestJSON, &policyDigest, &sourceRevision, &pointEpoch, &stateRevision, &currentEpoch); err != nil {
			return backupWriteError(err)
		}
		var manifest pendingCreationManifest
		if json.Unmarshal([]byte(manifestJSON), &manifest) != nil || manifest.CatalogDigest != request.CatalogDigest || manifest.DependencyInventoryDigest != request.DependencyDigest || manifest.KeyReferenceID != request.KeyReferenceID {
			return backupStoreError(generated.ErrorCodeIntegrityFailure, "backup-local-verification")
		}
		if manifestDigest != request.ManifestDigest || inventoryDigest != request.InventoryDigest || contentDigest != request.ContentDigest ||
			sourceRevision != request.SourceRevision || pointEpoch != request.Expected.RecoveryEpoch ||
			stateRevision != request.Expected.StateRevision || currentEpoch != request.Expected.RecoveryEpoch {
			return backupStoreError(generated.ErrorCodePlanStale, "backup-local-verification")
		}
		var canonicalPolicy string
		if err := tx.QueryRowContext(ctx, `SELECT canonical_json FROM backup_policy_drafts WHERE policy_digest=? AND recovery_epoch=?`, policyDigest, currentEpoch).Scan(&canonicalPolicy); err != nil {
			return backupStoreError(generated.ErrorCodePrerequisiteBlocked, "backup-local-verification-policy")
		}
		var policy generated.BackupPolicy
		if json.Unmarshal([]byte(canonicalPolicy), &policy) != nil || policy.SchemaVersion != "1.2.0" ||
			policy.FullPayloadIntervalHours < 1 || policy.FullPayloadIntervalHours > 8760 ||
			policy.FunctionalTestIntervalHours < 1 || policy.FunctionalTestIntervalHours > 8760 {
			return backupStoreError(generated.ErrorCodePrerequisiteBlocked, "backup-local-verification-cadence")
		}
		if status == "local-verified" {
			if !created.Before(request.FullReadAt.Add(time.Duration(policy.FullPayloadIntervalHours) * time.Hour)) {
				status = "full-payload-due"
			} else if !created.Before(request.FunctionalRestoredAt.Add(time.Duration(policy.FunctionalTestIntervalHours) * time.Hour)) {
				status = "functional-test-due"
			}
		}
		var leaseCount int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM backup_read_leases WHERE lease_id=? AND point_id=? AND repository_class=? AND state_revision=? AND recovery_epoch=? AND released_at IS NULL AND maximum_expires_at>?`, request.ReadLeaseID, request.PointID, class, stateRevision, currentEpoch, created.Format(time.RFC3339)).Scan(&leaseCount); err != nil {
			return backupWriteError(err)
		}
		if leaseCount != 1 {
			return backupStoreError(generated.ErrorCodePlanStale, "backup-local-verification")
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO backup_local_verifications(verification_id,proof_digest,point_id,run_id,read_lease_id,status,proof_class,manifest_digest,inventory_digest,observed_digest,content_digest,catalog_digest,dependency_digest,key_reference_id,source_revision,state_revision,recovery_epoch,full_read_at,functional_restored_at,reason_code,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			request.VerificationID, proofDigest, request.PointID, request.RunID, request.ReadLeaseID, status, request.ProofClass, request.ManifestDigest, request.InventoryDigest, request.ObservedDigest, request.ContentDigest, request.CatalogDigest, request.DependencyDigest, request.KeyReferenceID, request.SourceRevision, stateRevision, currentEpoch, formatOptional(request.FullReadAt), formatOptional(request.FunctionalRestoredAt), request.ReasonCode, created.Format(time.RFC3339))
		if err != nil {
			return backupWriteError(err)
		}
		receipt = LocalVerificationReceipt{VerificationID: request.VerificationID, ProofDigest: proofDigest, PointID: request.PointID, RepositoryClass: class, Status: status, ProofClass: request.ProofClass, ManifestDigest: request.ManifestDigest, InventoryDigest: request.InventoryDigest, StateRevision: stateRevision, RecoveryEpoch: currentEpoch}
		return nil
	})
	return receipt, err
}

// GetLocalVerificationByDigest binds an adapter effect to the exact immutable
// attempt it just appended, rather than accepting an older proof for the point.
func (repository *BackupRepository) GetLocalVerificationByDigest(ctx context.Context, digest string) (LocalVerificationReceipt, error) {
	var receipt LocalVerificationReceipt
	if repository == nil || repository.store == nil || !validBackupDigest(digest) {
		return receipt, backupStoreError(generated.ErrorCodeInputInvalid, "backup-local-verification")
	}
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT v.verification_id,v.proof_digest,v.point_id,p.repository_class,v.status,v.proof_class,v.manifest_digest,v.inventory_digest,v.state_revision,v.recovery_epoch FROM backup_local_verifications v JOIN recovery_points p ON p.point_id=v.point_id WHERE v.proof_digest=?`, digest).Scan(&receipt.VerificationID, &receipt.ProofDigest, &receipt.PointID, &receipt.RepositoryClass, &receipt.Status, &receipt.ProofClass, &receipt.ManifestDigest, &receipt.InventoryDigest, &receipt.StateRevision, &receipt.RecoveryEpoch)
	})
	return receipt, err
}

// CurrentLocalLastGood returns the compare-and-swap predecessor for one class.
// A missing row is represented by an empty verification ID.
func (repository *BackupRepository) CurrentLocalLastGood(ctx context.Context, class string) (string, error) {
	if repository == nil || repository.store == nil || (class != "standard" && class != "critical") {
		return "", backupStoreError(generated.ErrorCodeInputInvalid, "backup-last-good")
	}
	var id string
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT verification_id FROM backup_local_last_good WHERE repository_class=?`, class).Scan(&id)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return id, err
}

// AdvanceLocalLastGood is a separate CAS. A fixture, failed, uncertain, stale
// or second conflicting proof cannot replace a prior verified point.
func (repository *BackupRepository) AdvanceLocalLastGood(ctx context.Context, receipt LocalVerificationReceipt, expected RevisionToken, previousVerificationID string) error {
	if repository == nil || repository.store == nil || receipt.Status != "local-verified" || receipt.ProofClass != "live" || receipt.VerificationID == "" || receipt.PointID == "" || !validBackupDigest(receipt.ProofDigest) {
		return backupStoreError(generated.ErrorCodeInputInvalid, "backup-last-good")
	}
	return repository.inTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var revision, epoch int64
		if err := tx.QueryRowContext(ctx, `SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&revision, &epoch); err != nil {
			return backupWriteError(err)
		}
		if revision != expected.StateRevision || epoch != expected.RecoveryEpoch || revision != receipt.StateRevision || epoch != receipt.RecoveryEpoch {
			return backupStoreError(generated.ErrorCodePlanStale, "backup-last-good")
		}
		var fullText, restoredText, policyJSON string
		if err := tx.QueryRowContext(ctx, `SELECT v.full_read_at,v.functional_restored_at,d.canonical_json FROM backup_local_verifications v JOIN recovery_points p ON p.point_id=v.point_id JOIN backup_policy_drafts d ON d.policy_digest=p.policy_digest AND d.recovery_epoch=p.recovery_epoch WHERE v.verification_id=? AND v.proof_digest=? AND v.point_id=? AND p.repository_class=? AND v.status='local-verified' AND v.proof_class='live' AND v.state_revision=? AND v.recovery_epoch=? AND v.full_read_at IS NOT NULL AND v.functional_restored_at IS NOT NULL AND v.manifest_digest=p.manifest_digest AND v.inventory_digest=p.inventory_digest AND v.content_digest=p.content_digest`, receipt.VerificationID, receipt.ProofDigest, receipt.PointID, receipt.RepositoryClass, revision, epoch).Scan(&fullText, &restoredText, &policyJSON); err != nil {
			return backupStoreError(generated.ErrorCodePlanStale, "backup-last-good")
		}
		var policy generated.BackupPolicy
		fullAt, fullErr := time.Parse(time.RFC3339, fullText)
		restoredAt, restoreErr := time.Parse(time.RFC3339, restoredText)
		if json.Unmarshal([]byte(policyJSON), &policy) != nil || policy.SchemaVersion != "1.2.0" ||
			policy.FullPayloadIntervalHours < 1 || policy.FullPayloadIntervalHours > 8760 ||
			policy.FunctionalTestIntervalHours < 1 || policy.FunctionalTestIntervalHours > 8760 || fullErr != nil || restoreErr != nil ||
			!repository.store.config.Clock().UTC().Before(fullAt.Add(time.Duration(policy.FullPayloadIntervalHours)*time.Hour)) ||
			!repository.store.config.Clock().UTC().Before(restoredAt.Add(time.Duration(policy.FunctionalTestIntervalHours)*time.Hour)) {
			return backupStoreError(generated.ErrorCodePrerequisiteBlocked, "backup-last-good-cadence")
		}
		var current string
		err := tx.QueryRowContext(ctx, `SELECT verification_id FROM backup_local_last_good WHERE repository_class=?`, receipt.RepositoryClass).Scan(&current)
		if errors.Is(err, sql.ErrNoRows) {
			current = ""
		} else if err != nil {
			return backupWriteError(err)
		}
		if current != previousVerificationID || current == receipt.VerificationID {
			return backupStoreError(generated.ErrorCodeStateConflict, "backup-last-good")
		}
		stamp := repository.store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339)
		if current == "" {
			_, err = tx.ExecContext(ctx, `INSERT INTO backup_local_last_good(repository_class,point_id,verification_id,state_revision,recovery_epoch,advanced_at) VALUES(?,?,?,?,?,?)`, receipt.RepositoryClass, receipt.PointID, receipt.VerificationID, revision, epoch, stamp)
		} else {
			_, err = tx.ExecContext(ctx, `UPDATE backup_local_last_good SET point_id=?,verification_id=?,state_revision=?,recovery_epoch=?,advanced_at=? WHERE repository_class=? AND verification_id=?`, receipt.PointID, receipt.VerificationID, revision, epoch, stamp, receipt.RepositoryClass, current)
		}
		return backupWriteError(err)
	})
}
