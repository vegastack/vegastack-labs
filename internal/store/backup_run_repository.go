package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

// BackupWriterLeaseRequest asks for one exact single-writer lease bound to a
// running backup job for one repository at a recovery epoch.
type BackupWriterLeaseRequest struct {
	LeaseID          string
	JobID            string
	PolicyID         string
	PolicyDigest     string
	PlanID           string
	PlanDigest       string
	RunID            string
	StepID           string
	RepositoryID     string
	RepositoryClass  string
	TargetID         string
	SourceRevision   int64
	RecoveryEpoch    int64
	MaximumExpiresAt time.Time
}

// ExpectedObjectRow is one exact expected object in a pending point's inventory.
type ExpectedObjectRow struct {
	Type   string `json:"type"`
	Name   string `json:"name"`
	Bytes  int64  `json:"bytes"`
	Digest string `json:"digest"`
}

// PendingRecoveryPointRequest publishes exactly one pending point receipt bound
// to an active writer lease. It never carries verification evidence or last-good
// state; the store rejects any attempt to set them.
type PendingRecoveryPointRequest struct {
	LeaseID         string
	PointID         string
	SnapshotID      string
	SnapshotCount   int64
	ObjectCount     int64
	ObjectBytes     int64
	ContentDigest   string
	ManifestDigest  string
	ManifestJSON    []byte
	InventoryDigest string
	SourceRevision  int64
	RecoveryEpoch   int64
	SourceKind      string
	ProofClass      string
	ExpectedObjects []ExpectedObjectRow
}

// AcquireBackupWriterLease atomically records a running backup job and its single
// active writer lease. A second active lease for the same repository conflicts,
// giving before-effect two-writer exclusion.
func (repository *BackupRepository) AcquireBackupWriterLease(ctx context.Context, request BackupWriterLeaseRequest) error {
	if repository == nil || repository.store == nil || request.LeaseID == "" || request.JobID == "" ||
		!validBackupDigest(request.PolicyDigest) || !validBackupDigest(request.PlanDigest) ||
		(request.RepositoryClass != "standard" && request.RepositoryClass != "critical") || request.RecoveryEpoch < 0 {
		return backupStoreError(generated.ErrorCodeInputInvalid, "backup-writer-lease")
	}
	now := repository.store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339)
	return repository.inTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		// Reclaim any expired active lease on this physical root (a crashed run)
		// before acquiring, marking its still-open job uncertain; otherwise the
		// partial unique index would block the repository forever.
		if _, err := tx.ExecContext(ctx, `UPDATE backup_jobs SET status='uncertain', updated_at=? WHERE status IN ('queued','running') AND job_id IN (SELECT job_id FROM backup_writer_leases WHERE repository_class=? AND released_at IS NULL AND maximum_expires_at < ?)`, now, request.RepositoryClass, now); err != nil {
			return backupWriteError(err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE backup_writer_leases SET released_at=? WHERE repository_class=? AND released_at IS NULL AND maximum_expires_at < ?`, now, request.RepositoryClass, now); err != nil {
			return backupWriteError(err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE backup_read_leases SET released_at=? WHERE repository_class=? AND released_at IS NULL AND maximum_expires_at<=?`, now, request.RepositoryClass, now); err != nil {
			return backupWriteError(err)
		}
		var activeReaders int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM backup_read_leases WHERE repository_class=? AND released_at IS NULL`, request.RepositoryClass).Scan(&activeReaders); err != nil {
			return backupWriteError(err)
		}
		if activeReaders != 0 {
			return backupStoreError(generated.ErrorCodeStateConflict, "backup-writer-lease")
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO backup_jobs(job_id,policy_id,policy_digest,repository_id,repository_class,run_id,point_id,source_kind,proof_class,status,recovery_epoch,created_at,updated_at) VALUES(?,?,?,?,?,?,NULL,?,?,'running',?,?,?)`,
			request.JobID, request.PolicyID, request.PolicyDigest, request.RepositoryID, request.RepositoryClass, request.RunID, "local", "fixture", request.RecoveryEpoch, now, now); err != nil {
			return backupWriteError(err)
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO backup_writer_leases(lease_id,policy_id,policy_digest,job_id,point_id,plan_id,plan_digest,run_id,step_id,repository_id,repository_class,target_id,source_revision,recovery_epoch,maximum_expires_at,acquired_at,released_at) VALUES(?,?,?,?,NULL,?,?,?,?,?,?,?,?,?,?,?,NULL)`,
			request.LeaseID, request.PolicyID, request.PolicyDigest, request.JobID, request.PlanID, request.PlanDigest, request.RunID, request.StepID, request.RepositoryID, request.RepositoryClass, request.TargetID, request.SourceRevision, request.RecoveryEpoch, request.MaximumExpiresAt.UTC().Truncate(time.Second).Format(time.RFC3339), now)
		if err != nil {
			return backupWriteError(err)
		}
		return nil
	})
}

// AppendPendingRecoveryPoint publishes one immutable pending point receipt and
// its exact expected inventory in a single transaction, then closes the job and
// releases the lease. It verifies the active lease and that the bound policy
// draft is still present unchanged, and it never sets verification or last-good
// state. It returns only a sanitized point ID and the bound manifest digest.
func (repository *BackupRepository) AppendPendingRecoveryPoint(ctx context.Context, request PendingRecoveryPointRequest) (string, string, error) {
	if repository == nil || repository.store == nil || request.LeaseID == "" || request.PointID == "" || request.SnapshotID == "" ||
		!validBackupDigest(request.ContentDigest) || !validBackupDigest(request.ManifestDigest) || !validBackupDigest(request.InventoryDigest) ||
		request.SnapshotCount < 1 || request.ObjectCount < 0 || len(request.ExpectedObjects) == 0 {
		return "", "", backupStoreError(generated.ErrorCodeInputInvalid, "backup-pending-point")
	}
	// A #106 pending point is always local, fixture-class creation evidence. The
	// store forces these regardless of the caller; the DB CHECKs enforce the same
	// so a pending point can never be recorded as independent or live proof.
	if request.SourceKind != "local" || request.ProofClass != "fixture" {
		return "", "", backupStoreError(generated.ErrorCodeInputInvalid, "backup-pending-point-provenance")
	}
	// The canonical manifest bytes are persisted with the point and must reproduce
	// the bound manifest digest exactly, and the declared object count/bytes must
	// match the exact expected inventory — recomputed here, not trusted.
	if len(request.ManifestJSON) < 2 {
		return "", "", backupStoreError(generated.ErrorCodeInputInvalid, "backup-pending-point-manifest")
	}
	manifestSum := sha256.Sum256(request.ManifestJSON)
	if "sha256:"+hex.EncodeToString(manifestSum[:]) != request.ManifestDigest {
		return "", "", backupStoreError(generated.ErrorCodeIntegrityFailure, "backup-pending-point-manifest")
	}
	var inventoryBytes int64
	for _, object := range request.ExpectedObjects {
		if object.Name == "" || object.Bytes < 0 || !validBackupDigest(object.Digest) {
			return "", "", backupStoreError(generated.ErrorCodeIntegrityFailure, "backup-pending-point-inventory")
		}
		inventoryBytes += object.Bytes
	}
	if request.ObjectCount != int64(len(request.ExpectedObjects)) || request.ObjectBytes != inventoryBytes {
		return "", "", backupStoreError(generated.ErrorCodeIntegrityFailure, "backup-pending-point-inventory")
	}
	manifest, err := validatePendingManifest(request)
	if err != nil {
		return "", "", newStoreError(generated.ErrorCodeIntegrityFailure, "backup-pending-point-manifest", false, err)
	}
	now := repository.store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339)
	err = repository.inTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var jobID, policyID, policyDigest, repositoryID, repositoryClass, runID, stepID string
		var epoch, sourceRevision int64
		var expiresAt string
		err := tx.QueryRowContext(ctx, `SELECT job_id,policy_id,policy_digest,repository_id,repository_class,run_id,step_id,source_revision,recovery_epoch,maximum_expires_at FROM backup_writer_leases WHERE lease_id=? AND released_at IS NULL`, request.LeaseID).Scan(&jobID, &policyID, &policyDigest, &repositoryID, &repositoryClass, &runID, &stepID, &sourceRevision, &epoch, &expiresAt)
		if errors.Is(err, sql.ErrNoRows) {
			return backupStoreError(generated.ErrorCodePlanStale, "backup-writer-lease")
		}
		if err != nil {
			return backupWriteError(err)
		}
		if epoch != request.RecoveryEpoch || sourceRevision != request.SourceRevision ||
			manifest.PolicyID != policyID || manifest.PolicyDigest != policyDigest ||
			manifest.RepositoryID != repositoryID || manifest.RepositoryClass != repositoryClass ||
			manifest.RunID != runID || manifest.StepID != stepID || manifest.SourceRevision != sourceRevision ||
			expiresAt <= now {
			return backupStoreError(generated.ErrorCodePlanStale, "backup-writer-lease")
		}
		// The bound policy draft must still exist unchanged at this exact digest and epoch.
		var policyJSON string
		if err := tx.QueryRowContext(ctx, `SELECT canonical_json FROM backup_policy_drafts WHERE policy_digest=? AND recovery_epoch=?`, policyDigest, epoch).Scan(&policyJSON); err != nil {
			return backupStoreError(generated.ErrorCodeIntegrityFailure, "backup-policy-draft")
		}
		var policy generated.BackupPolicy
		policySum := sha256.Sum256([]byte(policyJSON))
		if "sha256:"+hex.EncodeToString(policySum[:]) != policyDigest ||
			json.Unmarshal([]byte(policyJSON), &policy) != nil || policy.PolicyID != policyID ||
			policy.RepositoryID == nil || *policy.RepositoryID != repositoryID || policy.RepositoryClass != repositoryClass ||
			policy.RecoveryEpoch != epoch || manifest.SourceID != policy.SourceID ||
			!slices.Equal(manifest.SourceSelectors, policy.SourceSelectors) ||
			policy.EncryptionKeyReferenceID == nil || manifest.KeyReferenceID != *policy.EncryptionKeyReferenceID ||
			len(manifest.ExpectedDependencies) != len(policy.Dependencies) {
			return backupStoreError(generated.ErrorCodeIntegrityFailure, "backup-policy-binding")
		}
		for index, dependency := range policy.Dependencies {
			if manifest.ExpectedDependencies[index] != (ExpectedDependencyRow{DependencyID: dependency.DependencyID, Kind: dependency.Kind, Digest: dependency.Digest}) {
				return backupStoreError(generated.ErrorCodeIntegrityFailure, "backup-policy-dependencies")
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO recovery_points(point_id,job_id,policy_id,policy_digest,repository_id,repository_class,source_kind,proof_class,snapshot_id,snapshot_count,object_count,object_bytes,content_digest,manifest_digest,manifest_json,inventory_digest,source_revision,recovery_epoch,verification_status,verified_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'pending',NULL,?)`,
			request.PointID, jobID, policyID, policyDigest, repositoryID, repositoryClass, request.SourceKind, request.ProofClass, request.SnapshotID, request.SnapshotCount, request.ObjectCount, request.ObjectBytes, request.ContentDigest, request.ManifestDigest, string(request.ManifestJSON), request.InventoryDigest, request.SourceRevision, epoch, now); err != nil {
			return backupWriteError(err)
		}
		for _, object := range request.ExpectedObjects {
			if _, err := tx.ExecContext(ctx, `INSERT INTO backup_expected_objects(point_id,object_type,object_name,object_bytes,object_digest) VALUES(?,?,?,?,?)`,
				request.PointID, object.Type, object.Name, object.Bytes, object.Digest); err != nil {
				return backupWriteError(err)
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE backup_jobs SET status='pending', point_id=?, updated_at=? WHERE job_id=?`, request.PointID, now, jobID); err != nil {
			return backupWriteError(err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE backup_writer_leases SET released_at=?, point_id=? WHERE lease_id=?`, now, request.PointID, request.LeaseID); err != nil {
			return backupWriteError(err)
		}
		return nil
	})
	if err != nil {
		return "", "", err
	}
	return request.PointID, request.ManifestDigest, nil
}

// PendingRecoveryPoint is a typed, secret-free readback of the immutable point
// receipt and its exact expected object inventory. It is always pending local
// fixture evidence; later independent verification lives in a separate record.
type PendingRecoveryPoint struct {
	PointID         string
	JobID           string
	PolicyID        string
	PolicyDigest    string
	RepositoryID    string
	RepositoryClass string
	ManifestDigest  string
	ManifestJSON    []byte
	ContentDigest   string
	InventoryDigest string
	ExpectedObjects []ExpectedObjectRow
	SourceRevision  int64
	RecoveryEpoch   int64
}

// GetPendingRecoveryPoint independently rechecks the durable manifest and
// inventory. The adapter uses this readback before confirming a run receipt.
func (repository *BackupRepository) GetPendingRecoveryPoint(ctx context.Context, pointID string) (PendingRecoveryPoint, error) {
	var point PendingRecoveryPoint
	if repository == nil || repository.store == nil || pointID == "" {
		return point, backupStoreError(generated.ErrorCodeInputInvalid, "backup-pending-point-read")
	}
	var request PendingRecoveryPointRequest
	var manifestJSON, sourceKind, proofClass, verificationStatus string
	var jobID, policyID, policyDigest, repositoryID, repositoryClass string
	var verifiedAt *string
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		if err := tx.queryRow(ctx, `SELECT point_id,job_id,policy_id,policy_digest,repository_id,repository_class,snapshot_id,snapshot_count,object_count,object_bytes,content_digest,manifest_digest,manifest_json,inventory_digest,source_revision,recovery_epoch,source_kind,proof_class,verification_status,verified_at FROM recovery_points WHERE point_id=?`, pointID).Scan(
			&request.PointID, &jobID, &policyID, &policyDigest, &repositoryID, &repositoryClass,
			&request.SnapshotID, &request.SnapshotCount, &request.ObjectCount, &request.ObjectBytes, &request.ContentDigest,
			&request.ManifestDigest, &manifestJSON, &request.InventoryDigest, &request.SourceRevision, &request.RecoveryEpoch,
			&sourceKind, &proofClass, &verificationStatus, &verifiedAt); err != nil {
			return err
		}
		rows, err := tx.query(ctx, `SELECT object_type,object_name,object_bytes,object_digest FROM backup_expected_objects WHERE point_id=?`, pointID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var object ExpectedObjectRow
			if err := rows.Scan(&object.Type, &object.Name, &object.Bytes, &object.Digest); err != nil {
				return err
			}
			request.ExpectedObjects = append(request.ExpectedObjects, object)
		}
		return rows.Err()
	})
	if errors.Is(err, sql.ErrNoRows) {
		return point, backupStoreError(generated.ErrorCodeResourceNotFound, "backup-pending-point-read")
	}
	if err != nil {
		return point, err
	}
	if sourceKind != "local" || proofClass != "fixture" || verificationStatus != "pending" || verifiedAt != nil {
		return point, backupStoreError(generated.ErrorCodeIntegrityFailure, "backup-pending-point-read")
	}
	request.ManifestJSON = []byte(manifestJSON)
	manifestSum := sha256.Sum256(request.ManifestJSON)
	if "sha256:"+hex.EncodeToString(manifestSum[:]) != request.ManifestDigest {
		return point, backupStoreError(generated.ErrorCodeIntegrityFailure, "backup-pending-point-read")
	}
	// Rows are read in primary-key order, while the manifest has canonical
	// capture order. Compare exact sets and then validate manifest bytes/order.
	var manifest pendingCreationManifest
	if json.Unmarshal(request.ManifestJSON, &manifest) != nil || len(manifest.ExpectedObjects) != len(request.ExpectedObjects) {
		return point, backupStoreError(generated.ErrorCodeIntegrityFailure, "backup-pending-point-read")
	}
	objects := make(map[ExpectedObjectRow]int, len(request.ExpectedObjects))
	for _, object := range request.ExpectedObjects {
		objects[object]++
	}
	for _, object := range manifest.ExpectedObjects {
		objects[object]--
	}
	for _, count := range objects {
		if count != 0 {
			return point, backupStoreError(generated.ErrorCodeIntegrityFailure, "backup-pending-point-read")
		}
	}
	request.ExpectedObjects = manifest.ExpectedObjects
	if _, err := validatePendingManifest(request); err != nil {
		return point, backupStoreError(generated.ErrorCodeIntegrityFailure, "backup-pending-point-read")
	}
	return PendingRecoveryPoint{PointID: pointID, JobID: jobID, PolicyID: policyID, PolicyDigest: policyDigest, RepositoryID: repositoryID, RepositoryClass: repositoryClass,
		ManifestDigest: request.ManifestDigest, ManifestJSON: request.ManifestJSON,
		ContentDigest:   request.ContentDigest,
		InventoryDigest: request.InventoryDigest, ExpectedObjects: request.ExpectedObjects,
		SourceRevision: request.SourceRevision, RecoveryEpoch: request.RecoveryEpoch}, nil
}

// VerifyActiveWriterLease confirms one writer lease is still the single active
// lease for its repository at the given epoch and has not passed its deadline.
// The REST object boundary calls it before every mutation (through a small
// adapter that owns the backup WriterLease type, keeping this package free of a
// dependency on the backup package).
func (repository *BackupRepository) VerifyActiveWriterLease(ctx context.Context, leaseID, repositoryID string, recoveryEpoch int64, now time.Time) error {
	if repository == nil || repository.store == nil || leaseID == "" || repositoryID == "" || recoveryEpoch < 0 {
		return backupStoreError(generated.ErrorCodeInputInvalid, "backup-writer-lease")
	}
	var maximumExpiresAt string
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT maximum_expires_at FROM backup_writer_leases WHERE lease_id=? AND repository_id=? AND recovery_epoch=? AND released_at IS NULL`, leaseID, repositoryID, recoveryEpoch).Scan(&maximumExpiresAt)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return backupStoreError(generated.ErrorCodePlanStale, "backup-writer-lease")
	}
	if err != nil {
		return err
	}
	deadline, err := time.Parse(time.RFC3339, maximumExpiresAt)
	if err != nil {
		return backupStoreError(generated.ErrorCodeIntegrityFailure, "backup-writer-lease")
	}
	if !now.Before(deadline) {
		return backupStoreError(generated.ErrorCodePlanStale, "backup-writer-lease")
	}
	return nil
}

// FailBackupJob records a failed or uncertain outcome, releases the lease, and
// preserves every prior point. It never prunes or deletes retained data.
func (repository *BackupRepository) FailBackupJob(ctx context.Context, leaseID, status string) error {
	if repository == nil || repository.store == nil || leaseID == "" || (status != "failed" && status != "uncertain") {
		return backupStoreError(generated.ErrorCodeInputInvalid, "backup-job-finish")
	}
	now := repository.store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339)
	return repository.inTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var jobID string
		err := tx.QueryRowContext(ctx, `SELECT job_id FROM backup_writer_leases WHERE lease_id=? AND released_at IS NULL`, leaseID).Scan(&jobID)
		if errors.Is(err, sql.ErrNoRows) {
			return backupStoreError(generated.ErrorCodeResourceNotFound, "backup-writer-lease")
		}
		if err != nil {
			return backupWriteError(err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE backup_jobs SET status=?, updated_at=? WHERE job_id=?`, status, now, jobID); err != nil {
			return backupWriteError(err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE backup_writer_leases SET released_at=? WHERE lease_id=?`, now, leaseID); err != nil {
			return backupWriteError(err)
		}
		return nil
	})
}

// inTx runs one serialized read-write backup transaction. Backup-domain tables
// enforce their own append-only, one-active-lease and pending-only invariants, so
// this deliberately does not advance the control-plane declaration revision.
func (repository *BackupRepository) inTx(ctx context.Context, business func(context.Context, *sql.Tx) error) error {
	store := repository.store
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.readyForTransaction(ctx); err != nil {
		return err
	}
	tx, err := store.conn.BeginTx(ctx, nil)
	if err != nil {
		return store.transactionError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := business(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return store.transactionError(ctx, err)
	}
	return nil
}

// backupWriteError classifies a driver error: a unique/constraint violation
// (for example a second active writer lease) maps to STATE_CONFLICT; everything
// else fails closed as an integrity failure.
func backupWriteError(err error) error {
	if err == nil {
		return nil
	}
	return classifySQLiteError(context.Background(), err)
}
