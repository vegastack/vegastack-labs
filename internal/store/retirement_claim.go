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

type LocalRetirementClaimRequest struct {
	IntentID, LeaseID, PlanID, PlanDigest, RunID, StepID string
	ExecutorLeaseID, RetentionConsumerID                 string
	RecoveryEpoch                                        int64
	MaximumExpiresAt                                     time.Time
	Attribution                                          audit.Attribution
}

type LocalRetirementLease struct {
	LeaseID, IntentID, PlanID, PlanDigest, RunID, StepID                            string
	RepositoryID, RepositoryClass, RetentionConsumerID                              string
	SourceRevision, RecoveryEpoch, MaxWorkObjects, MaxMutationBytes, MaxRepackBytes int64
	MaximumExpiresAt                                                                time.Time
	PlannedSnapshotIDs                                                              []string
}

func (repository *LocalRetirementRepository) ClaimLocalRetirement(ctx context.Context, request LocalRetirementClaimRequest) (LocalRetirementLease, error) {
	var lease LocalRetirementLease
	if repository == nil || repository.store == nil || !validRetirementID(request.IntentID) || !validRetirementID(request.LeaseID) ||
		!validRetirementID(request.PlanID) || !validBackupDigest(request.PlanDigest) || !validRetirementID(request.RunID) || !validRetirementID(request.StepID) ||
		!validRetirementID(request.ExecutorLeaseID) ||
		request.RetentionConsumerID != "backup-retention" || request.RecoveryEpoch < 0 || request.MaximumExpiresAt.IsZero() ||
		request.Attribution.AuthenticatedPrincipalID == "" || request.Attribution.AuthenticatedPrincipalMethod == "" {
		return lease, newStoreError(generated.ErrorCodeInputInvalid, "local-retirement-claim", false, nil)
	}
	now := repository.store.config.Clock().UTC().Truncate(time.Second)
	if !now.Before(request.MaximumExpiresAt) {
		return lease, newStoreError(generated.ErrorCodePlanStale, "local-retirement-claim", false, nil)
	}
	err := repository.inTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var intentPlan, intentDigest, canonical, repo, class, lockDigest, coverage, expectedInventory string
		var lockSequence, sourceRevision, stateRevision, epoch, maxWork, maxMutation, maxRepack, targetCount, survivorCount int64
		if err := tx.QueryRowContext(ctx, `SELECT plan_id,plan_digest,canonical_json,repository_id,repository_class,lock_catalog_digest,source_coverage_digest,expected_inventory_digest,lock_catalog_sequence,source_revision,state_revision,recovery_epoch,max_work_objects,max_mutation_bytes,max_repack_bytes,target_count,survivor_count FROM backup_retirement_intents WHERE intent_id=?`, request.IntentID).Scan(&intentPlan, &intentDigest, &canonical, &repo, &class, &lockDigest, &coverage, &expectedInventory, &lockSequence, &sourceRevision, &stateRevision, &epoch, &maxWork, &maxMutation, &maxRepack, &targetCount, &survivorCount); err != nil {
			return err
		}
		if intentPlan != request.PlanID || intentDigest != request.PlanDigest || epoch != request.RecoveryEpoch {
			return newStoreError(generated.ErrorCodePlanStale, "local-retirement-claim", false, nil)
		}
		var currentRevision, currentEpoch int64
		if err := tx.QueryRowContext(ctx, `SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&currentRevision, &currentEpoch); err != nil {
			return err
		}
		if currentRevision != stateRevision || currentEpoch != epoch {
			return newStoreError(generated.ErrorCodePlanStale, "local-retirement-claim", false, nil)
		}
		var currentLockDigest, currentCoverage, lockCanonical string
		var currentLockSequence int64
		if err := tx.QueryRowContext(ctx, `SELECT catalog_digest,source_coverage_digest,activation_sequence,canonical_json FROM backup_retention_lock_catalog_activations WHERE repository_class=? AND recovery_epoch=? ORDER BY activation_sequence DESC LIMIT 1`, class, epoch).Scan(&currentLockDigest, &currentCoverage, &currentLockSequence, &lockCanonical); err != nil || currentLockDigest != lockDigest || currentCoverage != coverage || currentLockSequence != lockSequence {
			return newStoreError(generated.ErrorCodePlanStale, "local-retirement-lock-catalog", false, err)
		}
		var appliedLocks LocalRetentionLockCatalog
		if json.Unmarshal([]byte(lockCanonical), &appliedLocks) != nil {
			return newStoreError(generated.ErrorCodeIntegrityFailure, "local-retirement-lock-catalog", false, nil)
		}
		lockBytes, verifiedLockDigest, lockErr := CanonicalLocalRetentionLockCatalog(appliedLocks)
		if lockErr != nil || string(lockBytes) != lockCanonical || verifiedLockDigest != lockDigest {
			return newStoreError(generated.ErrorCodePlanStale, "local-retirement-lock-catalog", false, lockErr)
		}
		var acknowledgementID, humanID, executorMaximum, planExpires, acknowledgementExpires string
		expiry := request.MaximumExpiresAt.Format(time.RFC3339)
		err := tx.QueryRowContext(ctx, `SELECT a.acknowledgement_id,a.human_id,e.maximum_expires_at,p.expires_at,a.expires_at
			FROM plan_runs r
			JOIN immutable_plans p ON p.plan_id=r.plan_id AND p.plan_digest=r.plan_digest
			JOIN plan_run_steps s ON s.run_id=r.run_id AND s.step_id=? AND s.status='running' AND s.effect_state='intent-recorded'
				AND s.operation_type='backup.local.retire' AND s.adapter_id='local.retention' AND s.target_id=?
				AND s.input_digest=(SELECT selection_digest FROM backup_retirement_intents WHERE intent_id=?) AND s.artifact_digest=? AND s.active_lease_id=?
			JOIN target_execution_leases e ON e.lease_id=? AND e.run_id=r.run_id AND e.step_id=s.step_id AND e.target_id=? AND e.recovery_epoch=? AND e.status='active'
			JOIN acknowledgement_requests a ON a.acknowledgement_id=r.acknowledgement_id AND a.plan_id=r.plan_id AND a.plan_digest=r.plan_digest
				AND a.target_digest=(SELECT selection_digest FROM backup_retirement_intents WHERE intent_id=?) AND a.state_revision=? AND a.recovery_epoch=?
				AND a.status='approved' AND a.consumed_at IS NOT NULL
			JOIN acknowledgement_proofs ap ON ap.acknowledgement_id=a.acknowledgement_id AND ap.status='approved'
			WHERE r.run_id=? AND r.plan_id=? AND r.plan_digest=? AND r.executor_mode='central' AND r.status='running'`, request.StepID, repo,
			request.IntentID, expectedInventory, request.ExecutorLeaseID, request.ExecutorLeaseID, repo, epoch, request.IntentID, stateRevision, epoch,
			request.RunID, request.PlanID, request.PlanDigest).Scan(&acknowledgementID, &humanID, &executorMaximum, &planExpires, &acknowledgementExpires)
		if err != nil || acknowledgementID == "" || humanID == "" {
			return newStoreError(generated.ErrorCodeAuthorizationDenied, "local-retirement-human-run", false, err)
		}
		for _, encoded := range []string{executorMaximum, planExpires, acknowledgementExpires} {
			deadline, parseErr := time.Parse(time.RFC3339, encoded)
			if parseErr != nil || request.MaximumExpiresAt.After(deadline) {
				return newStoreError(generated.ErrorCodePlanStale, "local-retirement-deadline", false, parseErr)
			}
		}
		var competing int
		if err := tx.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM backup_writer_leases WHERE repository_class=? AND released_at IS NULL)+(SELECT COUNT(*) FROM backup_read_leases WHERE repository_class=? AND released_at IS NULL)+(SELECT COUNT(*) FROM backup_retirement_leases WHERE repository_class=? AND released_at IS NULL)`, class, class, class).Scan(&competing); err != nil || competing != 0 {
			return newStoreError(generated.ErrorCodeStateConflict, "local-retirement-exclusive-lease", false, err)
		}
		var points int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM recovery_points WHERE repository_id=? AND repository_class=? AND recovery_epoch=?`, repo, class, epoch).Scan(&points); err != nil || int64(points) != targetCount+survivorCount {
			return newStoreError(generated.ErrorCodePlanStale, "local-retirement-point-set", false, err)
		}
		var staged struct {
			Selection retirementSelectionPayload
		}
		if json.Unmarshal([]byte(canonical), &staged) != nil || int64(len(staged.Selection.Targets)) != targetCount || int64(len(staged.Selection.Survivors)) != survivorCount {
			return newStoreError(generated.ErrorCodeIntegrityFailure, "local-retirement-selection", false, nil)
		}
		survivors := make(map[string]bool, len(staged.Selection.Survivors))
		for _, survivor := range staged.Selection.Survivors {
			survivors[survivor.PointID] = true
			var fullText, restoredText, policyJSON string
			if err := tx.QueryRowContext(ctx, `SELECT v.full_read_at,v.functional_restored_at,d.canonical_json
				FROM recovery_points p JOIN backup_local_verifications v ON v.point_id=p.point_id
				JOIN backup_policy_drafts d ON d.policy_digest=p.policy_digest AND d.recovery_epoch=p.recovery_epoch
				WHERE p.point_id=? AND p.snapshot_id=? AND p.repository_id=? AND p.repository_class=? AND p.manifest_digest=? AND p.inventory_digest=?
				AND p.source_revision=? AND p.recovery_epoch=? AND v.proof_digest=? AND v.status='local-verified' AND v.proof_class='live'
				AND v.manifest_digest=? AND v.inventory_digest=? AND v.dependency_digest=? AND v.state_revision=? AND v.recovery_epoch=?
				AND v.full_read_at IS NOT NULL AND v.functional_restored_at IS NOT NULL`, survivor.PointID, survivor.SnapshotID, repo, class,
				survivor.ManifestDigest, survivor.InventoryDigest, sourceRevision, epoch, survivor.ProofDigest, survivor.ManifestDigest,
				survivor.InventoryDigest, survivor.DependencyDigest, stateRevision, epoch).Scan(&fullText, &restoredText, &policyJSON); err != nil {
				return newStoreError(generated.ErrorCodePlanStale, "local-retirement-survivor-proof", false, err)
			}
			var policy generated.BackupPolicy
			fullAt, fullErr := time.Parse(time.RFC3339, fullText)
			restoredAt, restoreErr := time.Parse(time.RFC3339, restoredText)
			if json.Unmarshal([]byte(policyJSON), &policy) != nil || policy.SchemaVersion != "1.2.0" ||
				policy.FullPayloadIntervalHours < 1 || policy.FullPayloadIntervalHours > 8760 ||
				policy.FunctionalTestIntervalHours < 1 || policy.FunctionalTestIntervalHours > 8760 || fullErr != nil || restoreErr != nil ||
				!now.Before(fullAt.Add(time.Duration(policy.FullPayloadIntervalHours)*time.Hour)) ||
				!now.Before(restoredAt.Add(time.Duration(policy.FunctionalTestIntervalHours)*time.Hour)) {
				return newStoreError(generated.ErrorCodePrerequisiteBlocked, "local-retirement-survivor-cadence", false, nil)
			}
		}
		for _, target := range staged.Selection.Targets {
			var exact int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM recovery_points WHERE point_id=? AND snapshot_id=? AND repository_id=? AND repository_class=? AND manifest_digest=? AND inventory_digest=? AND source_revision=? AND recovery_epoch=?`,
				target.PointID, target.SnapshotID, repo, class, target.ManifestDigest, target.InventoryDigest, sourceRevision, epoch).Scan(&exact); err != nil || exact != 1 {
				return newStoreError(generated.ErrorCodePlanStale, "local-retirement-target", false, err)
			}
		}
		for _, lock := range appliedLocks.Locks {
			if !survivors[lock.PointID] {
				return newStoreError(generated.ErrorCodeAuthorizationDenied, "local-retirement-locked-point", false, nil)
			}
		}
		var lastGood string
		if err := tx.QueryRowContext(ctx, `SELECT point_id FROM backup_local_last_good WHERE repository_class=? AND recovery_epoch=?`, class, epoch).Scan(&lastGood); err != nil || !survivors[lastGood] {
			return newStoreError(generated.ErrorCodePrerequisiteBlocked, "local-retirement-last-good", false, err)
		}
		rows, err := tx.QueryContext(ctx, `SELECT json_extract(value,'$.SnapshotID') FROM json_each(json_extract(?,'$.Selection.Targets')) ORDER BY 1`, canonical)
		if err != nil {
			return err
		}
		defer rows.Close()
		var snapshots []string
		for rows.Next() {
			var id string
			if rows.Scan(&id) != nil || !validRetirementSnapshotID(id) {
				return newStoreError(generated.ErrorCodeIntegrityFailure, "local-retirement-targets", false, nil)
			}
			snapshots = append(snapshots, id)
		}
		if int64(len(snapshots)) != targetCount {
			return newStoreError(generated.ErrorCodeIntegrityFailure, "local-retirement-targets", false, nil)
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO backup_retirement_leases(lease_id,intent_id,run_id,step_id,executor_lease_id,acknowledgement_id,human_id,retention_consumer_id,repository_class,recovery_epoch,maximum_expires_at,acquired_at,released_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,NULL)`, request.LeaseID, request.IntentID, request.RunID, request.StepID, request.ExecutorLeaseID, acknowledgementID, humanID, request.RetentionConsumerID, class, epoch, expiry, now.Format(time.RFC3339))
		if err != nil {
			return err
		}
		lease = LocalRetirementLease{LeaseID: request.LeaseID, IntentID: request.IntentID, PlanID: request.PlanID, PlanDigest: request.PlanDigest, RunID: request.RunID, StepID: request.StepID, RepositoryID: repo, RepositoryClass: class, RetentionConsumerID: request.RetentionConsumerID, SourceRevision: sourceRevision, RecoveryEpoch: epoch, MaxWorkObjects: maxWork, MaxMutationBytes: maxMutation, MaxRepackBytes: maxRepack, MaximumExpiresAt: request.MaximumExpiresAt, PlannedSnapshotIDs: snapshots}
		return nil
	})
	return lease, err
}

func (repository *LocalRetirementRepository) VerifyLocalRetirementLease(ctx context.Context, leaseID string, epoch int64, now time.Time) error {
	if repository == nil || repository.store == nil || !validRetirementID(leaseID) {
		return newStoreError(generated.ErrorCodeInputInvalid, "local-retirement-lease", false, nil)
	}
	var expires string
	var current int64
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT l.maximum_expires_at,m.recovery_epoch FROM backup_retirement_leases l CROSS JOIN system_meta m WHERE m.id=1 AND l.lease_id=? AND l.recovery_epoch=? AND l.released_at IS NULL`, leaseID, epoch).Scan(&expires, &current)
	})
	if errors.Is(err, sql.ErrNoRows) || current != epoch {
		return newStoreError(generated.ErrorCodePlanStale, "local-retirement-lease", false, nil)
	}
	if err != nil {
		return err
	}
	deadline, e := time.Parse(time.RFC3339, expires)
	if e != nil || !now.Before(deadline) {
		return newStoreError(generated.ErrorCodePlanStale, "local-retirement-lease", false, nil)
	}
	return nil
}

func (repository *LocalRetirementRepository) inTx(ctx context.Context, business func(context.Context, *sql.Tx) error) error {
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
