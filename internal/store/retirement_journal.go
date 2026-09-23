package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

// LocalRetirementMutationAttempt is a write-ahead record, not an effect grant.
// Only a future exact retention adapter may connect this store journal to the
// REST role, after the human claim and full object inventory are implemented.
type LocalRetirementMutationAttempt struct {
	MutationID, LeaseID, MutationKind, ObjectType, ObjectName, ObjectDigest string
	Sequence, ObjectBytes, RecoveryEpoch                                    int64
	Attribution                                                             audit.Attribution
}

// BeginLocalMutation reserves exactly one lease-scoped sequence before any
// repository-visible PUT or quarantine rename. Reusing a sequence after a
// crash requires reconciliation; even byte-identical replay is rejected.
func (repository *LocalRetirementRepository) BeginLocalMutation(ctx context.Context, request LocalRetirementMutationAttempt) error {
	if repository == nil || repository.store == nil || !validRetirementID(request.MutationID) || !validRetirementID(request.LeaseID) ||
		request.Sequence < 1 || request.RecoveryEpoch < 0 || request.ObjectBytes < 1 || !validRetirementSnapshotID(request.ObjectName) ||
		!validBackupDigest(request.ObjectDigest) || (request.MutationKind != "put" && request.MutationKind != "delete") ||
		(request.ObjectType != "data" && request.ObjectType != "index" && request.ObjectType != "snapshots" && request.ObjectType != "locks") ||
		request.Attribution.AuthenticatedPrincipalID == "" || request.Attribution.AuthenticatedPrincipalMethod == "" {
		return newStoreError(generated.ErrorCodeInputInvalid, "local-retirement-mutation", false, nil)
	}
	if request.MutationKind == "put" && request.ObjectType == "snapshots" {
		return newStoreError(generated.ErrorCodeAuthorizationDenied, "local-retirement-mutation", false, nil)
	}
	key := audit.IntentKey{Scope: "local-retirement-mutation", KeyDigest: audit.Fingerprint(digestParts("retirement-mutation", request.MutationID)),
		RequestDigest: audit.Fingerprint(digestParts("retirement-mutation-request", request.LeaseID, strconv.FormatInt(request.Sequence, 10), request.MutationKind,
			request.ObjectType, request.ObjectName, request.ObjectDigest, strconv.FormatInt(request.ObjectBytes, 10), strconv.FormatInt(request.RecoveryEpoch, 10), request.Attribution.AuthenticatedPrincipalID))}
	after := audit.Fingerprint(request.ObjectDigest)
	event := audit.EventDraft{Type: "backup.retirement-mutation-begun", CorrelationID: request.LeaseID, Attribution: request.Attribution,
		Target: audit.Target{Kind: "backup-retirement-mutation", ID: request.MutationID}, After: &after}
	if audit.ValidateIntentKey(key) != nil || audit.ValidateEventDraft(event) != nil {
		return newStoreError(generated.ErrorCodeInputInvalid, "local-retirement-mutation-audit", false, nil)
	}
	nowTime := repository.store.config.Clock().UTC()
	now := nowTime.Truncate(time.Second).Format(time.RFC3339)
	result, err := repository.store.executeAuditIntent(ctx, intentRequest{Idempotency: key, Event: event}, false, func(ctx context.Context, tx *sql.Tx) error {
		var intentID, repositoryID, class, maxExpiry, planExpiry, executorExpiry, lockDigest, sourceCoverage string
		var stateRevision, epoch, maxWork, maxMutationBytes, maxRepackBytes, lockSequence int64
		err := tx.QueryRowContext(ctx, `SELECT l.intent_id,i.repository_id,l.repository_class,l.maximum_expires_at,p.expires_at,e.expires_at,
			i.lock_catalog_digest,i.source_coverage_digest,i.state_revision,l.recovery_epoch,i.max_work_objects,i.max_mutation_bytes,i.max_repack_bytes,i.lock_catalog_sequence
			FROM backup_retirement_leases l JOIN backup_retirement_intents i ON i.intent_id=l.intent_id
			JOIN plan_runs r ON r.run_id=l.run_id AND r.plan_id=i.plan_id AND r.plan_digest=i.plan_digest AND r.status='running'
			JOIN plan_run_steps s ON s.step_id=l.step_id AND s.run_id=r.run_id AND s.status='running' AND s.effect_state='intent-recorded' AND s.active_lease_id=l.executor_lease_id
			JOIN target_execution_leases e ON e.lease_id=l.executor_lease_id AND e.run_id=r.run_id AND e.step_id=s.step_id AND e.status='active'
			JOIN immutable_plans p ON p.plan_id=i.plan_id AND p.plan_digest=i.plan_digest
			WHERE l.lease_id=? AND l.released_at IS NULL`, request.LeaseID).Scan(&intentID, &repositoryID, &class, &maxExpiry, &planExpiry, &executorExpiry,
			&lockDigest, &sourceCoverage, &stateRevision, &epoch, &maxWork, &maxMutationBytes, &maxRepackBytes, &lockSequence)
		if errors.Is(err, sql.ErrNoRows) || epoch != request.RecoveryEpoch || !retirementDeadlineCurrent(maxExpiry, nowTime) ||
			!retirementDeadlineCurrent(planExpiry, nowTime) || !retirementDeadlineCurrent(executorExpiry, nowTime) {
			return newStoreError(generated.ErrorCodeRecoveryRequired, "local-retirement-mutation-lease", false, nil)
		}
		if err != nil {
			return err
		}
		var currentRevision, currentEpoch int64
		if err := tx.QueryRowContext(ctx, `SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&currentRevision, &currentEpoch); err != nil {
			return err
		}
		if currentRevision != stateRevision || currentEpoch != epoch {
			return newStoreError(generated.ErrorCodePlanStale, "local-retirement-mutation", false, nil)
		}
		var activeLockDigest, activeCoverage string
		var activeLockSequence int64
		if err := tx.QueryRowContext(ctx, `SELECT catalog_digest,source_coverage_digest,activation_sequence FROM backup_retention_lock_catalog_activations
			WHERE repository_class=? AND recovery_epoch=? ORDER BY activation_sequence DESC LIMIT 1`, class, epoch).
			Scan(&activeLockDigest, &activeCoverage, &activeLockSequence); err != nil || activeLockDigest != lockDigest || activeCoverage != sourceCoverage || activeLockSequence != lockSequence {
			return newStoreError(generated.ErrorCodePlanStale, "local-retirement-lock-catalog", false, err)
		}
		var canonical string
		if err := tx.QueryRowContext(ctx, `SELECT canonical_json FROM backup_retirement_intents WHERE intent_id=?`, intentID).Scan(&canonical); err != nil {
			return err
		}
		var staged struct {
			Selection retirementSelectionPayload
		}
		if json.Unmarshal([]byte(canonical), &staged) != nil {
			return newStoreError(generated.ErrorCodeIntegrityFailure, "local-retirement-intent", false, nil)
		}
		var count, totalBytes, repackBytes, unresolved, adverse int64
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(object_bytes),0),COALESCE(SUM(CASE WHEN mutation_kind='put' AND object_type IN ('data','index') THEN object_bytes ELSE 0 END),0),
			COALESCE(SUM(CASE WHEN o.mutation_id IS NULL THEN 1 ELSE 0 END),0),COALESCE(SUM(CASE WHEN o.status IN ('denied','uncertain') THEN 1 ELSE 0 END),0)
			FROM backup_retirement_mutation_attempts a LEFT JOIN backup_retirement_mutation_outcomes o ON o.mutation_id=a.mutation_id WHERE a.lease_id=?`, request.LeaseID).
			Scan(&count, &totalBytes, &repackBytes, &unresolved, &adverse); err != nil {
			return err
		}
		if unresolved != 0 || adverse != 0 || request.Sequence != count+1 || count >= maxWork || request.ObjectBytes > maxMutationBytes-totalBytes ||
			(request.MutationKind == "put" && (request.ObjectType == "data" || request.ObjectType == "index") && request.ObjectBytes > maxRepackBytes-repackBytes) {
			return newStoreError(generated.ErrorCodePrerequisiteBlocked, "local-retirement-mutation-bound", false, nil)
		}
		if request.MutationKind == "delete" && request.ObjectType != "locks" {
			var listed, createdEarlier int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM backup_expected_objects o JOIN recovery_points p ON p.point_id=o.point_id
				WHERE p.repository_id=? AND p.repository_class=? AND p.recovery_epoch=? AND o.object_type=? AND o.object_name=? AND o.object_digest=? AND o.object_bytes=?`,
				repositoryID, class, epoch, request.ObjectType, request.ObjectName, request.ObjectDigest, request.ObjectBytes).Scan(&listed); err != nil {
				return err
			}
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM backup_retirement_mutation_attempts a
				JOIN backup_retirement_mutation_outcomes o ON o.mutation_id=a.mutation_id AND o.status='created'
				WHERE a.lease_id=? AND a.mutation_kind='put' AND a.object_type=? AND a.object_name=? AND a.object_digest=? AND a.object_bytes=?`,
				request.LeaseID, request.ObjectType, request.ObjectName, request.ObjectDigest, request.ObjectBytes).Scan(&createdEarlier); err != nil {
				return err
			}
			if listed == 0 && createdEarlier == 0 {
				return newStoreError(generated.ErrorCodePrerequisiteBlocked, "local-retirement-unlisted-object", false, nil)
			}
			for _, survivor := range staged.Selection.Survivors {
				var dependency int
				if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM backup_expected_objects
					WHERE point_id=? AND object_type=? AND object_name=? AND object_digest=? AND object_bytes=?`, survivor.PointID,
					request.ObjectType, request.ObjectName, request.ObjectDigest, request.ObjectBytes).Scan(&dependency); err != nil {
					return err
				}
				if dependency != 0 {
					return newStoreError(generated.ErrorCodeAuthorizationDenied, "local-retirement-survivor-dependency", false, nil)
				}
			}
		}
		if request.ObjectType == "snapshots" {
			listed := false
			for _, target := range staged.Selection.Targets {
				if target.SnapshotID != request.ObjectName {
					continue
				}
				var exact int
				if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM recovery_points WHERE point_id=? AND snapshot_id=? AND manifest_digest=? AND repository_id=? AND repository_class=? AND recovery_epoch=?`,
					target.PointID, target.SnapshotID, target.ManifestDigest, repositoryID, class, epoch).Scan(&exact); err != nil {
					return err
				}
				listed = exact == 1
			}
			if !listed {
				return newStoreError(generated.ErrorCodeAuthorizationDenied, "local-retirement-snapshot", false, nil)
			}
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO backup_retirement_mutation_attempts(mutation_id,lease_id,sequence,mutation_kind,object_type,object_name,object_digest,object_bytes,recovery_epoch,begun_at)
			VALUES(?,?,?,?,?,?,?,?,?,?)`, request.MutationID, request.LeaseID, request.Sequence, request.MutationKind, request.ObjectType, request.ObjectName,
			request.ObjectDigest, request.ObjectBytes, request.RecoveryEpoch, now)
		return err
	})
	if err != nil {
		return err
	}
	if !result.Created {
		return newStoreError(generated.ErrorCodeRecoveryRequired, "local-retirement-mutation-replay", false, nil)
	}
	return nil
}

type LocalRetirementMutationOutcome struct {
	MutationID, LeaseID, Status, QuarantineName string
	Attribution                                 audit.Attribution
}

// FinishLocalMutation records what the guarded REST server observed. It does
// not infer an outcome from a missing response, release the retention lease,
// or publish a successor inventory. An absent row remains uncertain.
func (repository *LocalRetirementRepository) FinishLocalMutation(ctx context.Context, request LocalRetirementMutationOutcome) error {
	if repository == nil || repository.store == nil || !validRetirementID(request.MutationID) || !validRetirementID(request.LeaseID) ||
		request.Attribution.AuthenticatedPrincipalID == "" || request.Attribution.AuthenticatedPrincipalMethod == "" ||
		(request.Status != "created" && request.Status != "quarantined" && request.Status != "denied" && request.Status != "uncertain") {
		return newStoreError(generated.ErrorCodeInputInvalid, "local-retirement-mutation-outcome", false, nil)
	}
	key := audit.IntentKey{Scope: "local-retirement-mutation-outcome", KeyDigest: audit.Fingerprint(digestParts("retirement-outcome", request.MutationID)),
		RequestDigest: audit.Fingerprint(digestParts("retirement-outcome-request", request.MutationID, request.LeaseID, request.Status, request.QuarantineName, request.Attribution.AuthenticatedPrincipalID))}
	after := audit.Fingerprint(digestParts("retirement-outcome-status", request.Status, request.QuarantineName))
	event := audit.EventDraft{Type: "backup.retirement-mutation-observed", CorrelationID: request.LeaseID, Attribution: request.Attribution,
		Target: audit.Target{Kind: "backup-retirement-mutation", ID: request.MutationID}, After: &after}
	if audit.ValidateIntentKey(key) != nil || audit.ValidateEventDraft(event) != nil {
		return newStoreError(generated.ErrorCodeInputInvalid, "local-retirement-outcome-audit", false, nil)
	}
	now := repository.store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339)
	result, err := repository.store.executeAuditIntent(ctx, intentRequest{Idempotency: key, Event: event}, false, func(ctx context.Context, tx *sql.Tx) error {
		var kind, objectType, objectName string
		if err := tx.QueryRowContext(ctx, `SELECT mutation_kind,object_type,object_name FROM backup_retirement_mutation_attempts WHERE mutation_id=? AND lease_id=?`,
			request.MutationID, request.LeaseID).Scan(&kind, &objectType, &objectName); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return newStoreError(generated.ErrorCodePrerequisiteBlocked, "local-retirement-unbegun-mutation", false, nil)
			}
			return err
		}
		if (request.Status == "created" && kind != "put") || (request.Status == "quarantined" && kind != "delete") ||
			(request.Status == "quarantined" && request.QuarantineName != objectType+"/"+objectName) ||
			(request.Status != "quarantined" && request.QuarantineName != "") {
			return newStoreError(generated.ErrorCodeInputInvalid, "local-retirement-mutation-outcome", false, nil)
		}
		var quarantine any
		if request.Status == "quarantined" {
			quarantine = request.QuarantineName
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO backup_retirement_mutation_outcomes(mutation_id,status,quarantine_name,observed_digest,recorded_at) VALUES(?,?,?,NULL,?)`,
			request.MutationID, request.Status, quarantine, now)
		return err
	})
	if err != nil {
		return err
	}
	if !result.Created {
		return newStoreError(generated.ErrorCodeStateConflict, "local-retirement-outcome-replay", false, nil)
	}
	return nil
}
