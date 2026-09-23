package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

// ReadLocalBackupStatus projects immutable local records into the generated,
// sanitized API shape. Due dates come only from policy-bound observed checks.
func (repository *BackupRepository) ReadLocalBackupStatus(ctx context.Context) (generated.BackupStatusData, error) {
	return repository.readLocalBackupStatus(ctx, nil)
}

// ReadLocalBackupStatusScoped rechecks the read grant in the same SQLite
// snapshot as the projection, closing the gap between API admission and read.
func (repository *BackupRepository) ReadLocalBackupStatusScoped(ctx context.Context, scope authorization.ReadScope) (generated.BackupStatusData, error) {
	if scope.Capability != "backup.read" || scope.ResourceKind != "backup" {
		return generated.BackupStatusData{}, backupStoreError(generated.ErrorCodeAuthorizationDenied, "backup-status")
	}
	return repository.readLocalBackupStatus(ctx, &scope)
}

func (repository *BackupRepository) readLocalBackupStatus(ctx context.Context, scope *authorization.ReadScope) (generated.BackupStatusData, error) {
	status := generated.BackupStatusData{Schema: generated.SchemaIDBackupStatusData, SchemaVersion: "1.2.0",
		Policies: []generated.BackupPolicy{}, Jobs: []generated.BackupJob{},
		Verifications: []generated.BackupVerificationAttempt{}, LastGood: []generated.BackupLastGood{},
		Retirements: []generated.BackupLocalRetirementStatus{}}
	if repository == nil || repository.store == nil {
		return status, backupStoreError(generated.ErrorCodeInputInvalid, "backup-status")
	}
	now := repository.store.config.Clock().UTC()
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		if scope != nil {
			if err := verifyReadScope(ctx, tx, *scope, "current"); err != nil {
				return err
			}
		}
		if err := tx.queryRow(ctx, `SELECT recovery_epoch FROM system_meta WHERE id=1`).Scan(&status.RecoveryEpoch); err != nil {
			return err
		}
		policies := map[string]generated.BackupPolicy{}
		policyRows, err := tx.query(ctx, `SELECT policy_digest,canonical_json FROM backup_policy_drafts WHERE recovery_epoch=? ORDER BY created_at DESC,draft_id DESC LIMIT 257`, status.RecoveryEpoch)
		if err != nil {
			return err
		}
		for policyRows.Next() {
			var digest, canonical string
			if err := policyRows.Scan(&digest, &canonical); err != nil {
				policyRows.Close()
				return err
			}
			sum := sha256.Sum256([]byte(canonical))
			if "sha256:"+hex.EncodeToString(sum[:]) != digest {
				policyRows.Close()
				return backupStoreError(generated.ErrorCodeIntegrityFailure, "backup-status-policy")
			}
			var policy generated.BackupPolicy
			if json.Unmarshal([]byte(canonical), &policy) != nil {
				policyRows.Close()
				return backupStoreError(generated.ErrorCodeIntegrityFailure, "backup-status-policy")
			}
			if policy.SchemaVersion == "1.2.0" {
				if validateBackupPolicy(policy, status.RecoveryEpoch) != nil {
					policyRows.Close()
					return backupStoreError(generated.ErrorCodeIntegrityFailure, "backup-status-policy")
				}
				status.Policies = append(status.Policies, policy)
				policies[digest] = policy
			}
		}
		if err := policyRows.Err(); err != nil {
			policyRows.Close()
			return err
		}
		policyRows.Close()
		if len(status.Policies) > 256 {
			return backupStoreError(generated.ErrorCodePrerequisiteBlocked, "backup-status-limit")
		}
		jobRows, err := tx.query(ctx, `SELECT job_id,policy_id,run_id,point_id,source_kind,proof_class,status,recovery_epoch FROM backup_jobs WHERE recovery_epoch=? ORDER BY created_at DESC,job_id DESC LIMIT 257`, status.RecoveryEpoch)
		if err != nil {
			return err
		}
		jobIndex := map[string]int{}
		for jobRows.Next() {
			job := generated.BackupJob{Schema: generated.SchemaIDBackupJob, SchemaVersion: "1.1.0"}
			var runID, pointID sql.NullString
			if err := jobRows.Scan(&job.JobID, &job.PolicyID, &runID, &pointID, &job.SourceKind, &job.ProofClass, &job.Status, &job.RecoveryEpoch); err != nil {
				jobRows.Close()
				return err
			}
			job.RunID, job.PointID = nullableString(runID), nullableString(pointID)
			jobIndex[job.JobID] = len(status.Jobs)
			status.Jobs = append(status.Jobs, job)
		}
		if err := jobRows.Err(); err != nil {
			jobRows.Close()
			return err
		}
		jobRows.Close()
		if len(status.Jobs) > 256 {
			return backupStoreError(generated.ErrorCodePrerequisiteBlocked, "backup-status-limit")
		}
		verifyRows, err := tx.query(ctx, `SELECT v.verification_id,p.job_id,v.point_id,v.run_id,v.status,v.proof_class,v.proof_digest,v.functional_restored_at,v.full_read_at,p.policy_digest,NULLIF(v.reason_code,''),v.recovery_epoch FROM backup_local_verifications v JOIN recovery_points p ON p.point_id=v.point_id WHERE v.recovery_epoch=? ORDER BY v.created_at DESC,v.verification_id DESC LIMIT 257`, status.RecoveryEpoch)
		if err != nil {
			return err
		}
		seenJob := map[string]bool{}
		for verifyRows.Next() {
			attempt := generated.BackupVerificationAttempt{Schema: generated.SchemaIDBackupVerificationAttempt, SchemaVersion: "1.2.0"}
			var runID, restoredAt, fullAt, reasonCode sql.NullString
			var digest, policyDigest string
			if err := verifyRows.Scan(&attempt.VerificationID, &attempt.JobID, &attempt.PointID, &runID, &attempt.Status,
				&attempt.ProofClass, &digest, &restoredAt, &fullAt, &policyDigest, &reasonCode, &attempt.RecoveryEpoch); err != nil {
				verifyRows.Close()
				return err
			}
			attempt.RunID = nullableString(runID)
			attempt.VerificationDigest = &digest
			attempt.ReasonCode = nullableString(reasonCode)
			if attempt.ReasonCode != nil && !validRunToken(*attempt.ReasonCode) {
				verifyRows.Close()
				return backupStoreError(generated.ErrorCodeIntegrityFailure, "backup-status-reason-code")
			}
			if attempt.Status == "local-verified" {
				policy, ok := policies[policyDigest]
				if !ok || !fullAt.Valid || !restoredAt.Valid {
					verifyRows.Close()
					return backupStoreError(generated.ErrorCodeIntegrityFailure, "backup-status-cadence")
				}
				fullTime, fullErr := time.Parse(time.RFC3339, fullAt.String)
				restoreTime, restoreErr := time.Parse(time.RFC3339, restoredAt.String)
				if fullErr != nil || restoreErr != nil {
					verifyRows.Close()
					return backupStoreError(generated.ErrorCodeIntegrityFailure, "backup-status-cadence")
				}
				fullDue := fullTime.Add(time.Duration(policy.FullPayloadIntervalHours) * time.Hour)
				functionalDue := restoreTime.Add(time.Duration(policy.FunctionalTestIntervalHours) * time.Hour)
				fullText, functionalText := fullDue.UTC().Format(time.RFC3339), functionalDue.UTC().Format(time.RFC3339)
				attempt.VerifiedAt = &restoredAt.String
				attempt.FullPayloadDueAt, attempt.FunctionalTestDueAt = &fullText, &functionalText
				if !now.Before(fullDue) {
					attempt.Status = "full-payload-due"
				} else if !now.Before(functionalDue) {
					attempt.Status = "functional-test-due"
				}
			}
			if !seenJob[attempt.JobID] {
				seenJob[attempt.JobID] = true
				if index, ok := jobIndex[attempt.JobID]; ok {
					status.Jobs[index].VerificationDigest = &digest
					if attempt.Status == "local-verified" {
						status.Jobs[index].Status = "verified"
					}
				}
			}
			status.Verifications = append(status.Verifications, attempt)
		}
		if err := verifyRows.Err(); err != nil {
			verifyRows.Close()
			return err
		}
		verifyRows.Close()
		if len(status.Verifications) > 256 {
			return backupStoreError(generated.ErrorCodePrerequisiteBlocked, "backup-status-limit")
		}
		lastRows, err := tx.query(ctx, `SELECT g.repository_class,g.point_id,g.verification_id,p.manifest_digest,g.recovery_epoch FROM backup_local_last_good g JOIN recovery_points p ON p.point_id=g.point_id WHERE g.recovery_epoch=? ORDER BY g.repository_class`, status.RecoveryEpoch)
		if err != nil {
			return err
		}
		for lastRows.Next() {
			last := generated.BackupLastGood{Schema: generated.SchemaIDBackupLastGood, SchemaVersion: "1.1.0"}
			if err := lastRows.Scan(&last.RepositoryClass, &last.PointID, &last.VerificationID, &last.ManifestDigest, &last.RecoveryEpoch); err != nil {
				lastRows.Close()
				return err
			}
			status.LastGood = append(status.LastGood, last)
		}
		err = lastRows.Err()
		lastRows.Close()
		if err != nil {
			return err
		}
		retirementRows, err := tx.query(ctx, `SELECT intent_id,repository_id,repository_class,selection_digest,lock_catalog_digest,lock_catalog_sequence,source_coverage_digest,expected_inventory_digest,canonical_json,expected_reclaim_bytes,recovery_epoch FROM backup_retirement_intents WHERE recovery_epoch=? ORDER BY created_at DESC,intent_id DESC LIMIT 257`, status.RecoveryEpoch)
		if err != nil {
			return err
		}
		defer retirementRows.Close()
		for retirementRows.Next() {
			item := generated.BackupLocalRetirementStatus{Schema: generated.SchemaIDBackupLocalRetirementStatus, SchemaVersion: "1.1.0", Status: "planned", TargetPointIDs: []string{}, SurvivorPointIDs: []string{}}
			var canonical string
			if err := retirementRows.Scan(&item.IntentID, &item.RepositoryID, &item.RepositoryClass, &item.SelectionDigest, &item.LockCatalogDigest,
				&item.LockCatalogSequence, &item.SourceCoverageDigest, &item.ExpectedInventoryDigest, &canonical, &item.ExpectedReclaimBytes, &item.RecoveryEpoch); err != nil {
				return err
			}
			var staged struct {
				Selection retirementSelectionPayload
			}
			if json.Unmarshal([]byte(canonical), &staged) != nil {
				return backupStoreError(generated.ErrorCodeIntegrityFailure, "backup-status-retirement")
			}
			for _, target := range staged.Selection.Targets {
				item.TargetPointIDs = append(item.TargetPointIDs, target.PointID)
			}
			for _, survivor := range staged.Selection.Survivors {
				item.SurvivorPointIDs = append(item.SurvivorPointIDs, survivor.PointID)
			}
			var journal, proof sql.NullString
			receiptErr := tx.queryRow(ctx, `SELECT status,journal_digest,proof_digest FROM backup_retirement_receipts WHERE intent_id=? ORDER BY recorded_at DESC,receipt_id DESC LIMIT 1`, item.IntentID).
				Scan(&item.Status, &journal, &proof)
			if receiptErr != nil && !errors.Is(receiptErr, sql.ErrNoRows) {
				return receiptErr
			}
			if errors.Is(receiptErr, sql.ErrNoRows) {
				var active int
				if err := tx.queryRow(ctx, `SELECT COUNT(*) FROM backup_retirement_leases WHERE intent_id=? AND released_at IS NULL`, item.IntentID).Scan(&active); err != nil {
					return err
				}
				if active != 0 {
					item.Status = "in-progress"
				}
			}
			item.JournalDigest, item.SurvivorVerificationDigest = nullableString(journal), nullableString(proof)
			status.Retirements = append(status.Retirements, item)
		}
		if err := retirementRows.Err(); err != nil {
			return err
		}
		if len(status.Retirements) > 256 {
			return backupStoreError(generated.ErrorCodePrerequisiteBlocked, "backup-status-limit")
		}
		return nil
	})
	return status, err
}

func nullableString(value sql.NullString) *string {
	if !value.Valid {
		return nil
	}
	return &value.String
}
