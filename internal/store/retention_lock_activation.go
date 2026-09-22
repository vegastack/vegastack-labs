package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

type LocalRetentionLockActivationRequest struct {
	Catalog                            LocalRetentionLockCatalog
	PlanID, PlanDigest, RunID, StepID  string
	ExecutorLeaseID, AcknowledgementID string
	HumanID                            string
	Expected                           RevisionToken
	Attribution                        audit.Attribution
}

// ActivateLocalRetentionLockCatalog records one complete generation while an
// exact destructive human run owns the central step lease. The catalog is not
// readable authority until that run and step have both succeeded.
func (repository *LocalRetirementRepository) ActivateLocalRetentionLockCatalog(ctx context.Context, request LocalRetentionLockActivationRequest) (string, error) {
	if repository == nil || repository.store == nil || !validRetirementID(request.PlanID) || !validBackupDigest(request.PlanDigest) ||
		!validRetirementID(request.RunID) || !validRetirementID(request.StepID) || !validRetirementID(request.ExecutorLeaseID) ||
		!validRetirementID(request.AcknowledgementID) || !validRetirementID(request.HumanID) ||
		request.Expected.StateRevision < 1 || request.Expected.RecoveryEpoch != request.Catalog.RecoveryEpoch ||
		request.Attribution.AuthenticatedPrincipalID == "" || request.Attribution.AuthenticatedPrincipalMethod == "" ||
		(request.Attribution.AuthenticatedPrincipalID != request.HumanID &&
			(request.Attribution.ResponsibleHumanPrincipalID == nil || *request.Attribution.ResponsibleHumanPrincipalID != request.HumanID)) {
		return "", newStoreError(generated.ErrorCodeInputInvalid, "local-retention-lock-activation", false, nil)
	}
	canonical, catalogDigest, err := CanonicalLocalRetentionLockCatalog(request.Catalog)
	if err != nil {
		return "", err
	}
	targetDigest, err := localRepositoryPlanTargetDigest(request.Catalog.RepositoryID)
	if err != nil {
		return "", newStoreError(generated.ErrorCodeInputInvalid, "local-retention-lock-plan-target", false, err)
	}
	sum := sha256.Sum256([]byte(request.PlanID + "\x00" + request.RunID + "\x00" + catalogDigest))
	activationID := "lock-catalog-" + hex.EncodeToString(sum[:16])
	key := audit.IntentKey{Scope: "local-retention-lock-activation", KeyDigest: audit.Fingerprint(digestParts("lock-catalog-activation-key", request.PlanID)),
		RequestDigest: audit.Fingerprint(digestParts("lock-catalog-activation", request.RunID, request.StepID, request.AcknowledgementID, request.HumanID, catalogDigest))}
	after := audit.Fingerprint(catalogDigest)
	event := audit.EventDraft{Type: "backup.retention-lock-catalog-activated", CorrelationID: request.RunID, Attribution: request.Attribution,
		Target: audit.Target{Kind: "backup-retention-lock-catalog", ID: activationID}, After: &after}
	if audit.ValidateIntentKey(key) != nil || audit.ValidateEventDraft(event) != nil {
		return "", newStoreError(generated.ErrorCodeInputInvalid, "local-retention-lock-audit", false, nil)
	}
	nowTime := repository.store.config.Clock().UTC()
	now := nowTime.Truncate(time.Second).Format(time.RFC3339)
	result, err := repository.store.executeAuditIntent(ctx, intentRequest{Expected: &request.Expected, Idempotency: key, Event: event}, false, func(ctx context.Context, tx *sql.Tx) error {
		var planBytes []byte
		var readable, expires string
		err := tx.QueryRowContext(ctx, `SELECT p.canonical_bytes,p.readable_plan,p.expires_at FROM immutable_plans p
			JOIN declaration_revisions d ON d.declaration_id=p.declaration_id AND d.declaration_revision=p.declaration_revision
			WHERE p.plan_id=? AND p.plan_digest=? AND p.state_revision=? AND p.recovery_epoch=? AND
			d.declaration_type='backup.retention-locks' AND d.status='committed'`,
			request.PlanID, request.PlanDigest, request.Expected.StateRevision, request.Expected.RecoveryEpoch).Scan(&planBytes, &readable, &expires)
		if errors.Is(err, sql.ErrNoRows) {
			return newStoreError(generated.ErrorCodePrerequisiteBlocked, "local-retention-lock-plan", false, nil)
		}
		if err != nil {
			return err
		}
		var plan generated.Plan
		if !decodeStoredPlan(planBytes, readable, &plan) || !retirementDeadlineCurrent(expires, nowTime) ||
			plan.AuthorizationBranch != "human" || plan.Risk != "destructive" || plan.ExecutorMode != "central" ||
			plan.Binding.TargetDigest != targetDigest || plan.Binding.DeclarationRevision != request.Catalog.Revision ||
			len(plan.Operations) != 1 || plan.Operations[0].OperationType != "backup.retention-locks.activate" ||
			plan.Operations[0].AdapterID != "core.retention-locks" || plan.Operations[0].TargetID != request.Catalog.RepositoryID ||
			plan.Operations[0].InputDigest != catalogDigest || plan.Operations[0].ArtifactDigest != request.Catalog.SourceCoverageDigest {
			return newStoreError(generated.ErrorCodePrerequisiteBlocked, "local-retention-lock-plan", false, nil)
		}
		var leaseExpires string
		err = tx.QueryRowContext(ctx, `SELECT e.expires_at FROM plan_runs r
			JOIN plan_run_steps s ON s.run_id=r.run_id AND s.step_id=? AND s.status='running' AND s.effect_state='intent-recorded' AND
				s.operation_type='backup.retention-locks.activate' AND s.adapter_id='core.retention-locks' AND s.target_id=? AND s.input_digest=? AND s.artifact_digest=? AND s.active_lease_id=?
			JOIN target_execution_leases e ON e.lease_id=? AND e.run_id=r.run_id AND e.step_id=s.step_id AND e.target_id=? AND e.recovery_epoch=? AND e.status='active'
			JOIN acknowledgement_requests a ON a.acknowledgement_id=r.acknowledgement_id AND a.plan_id=r.plan_id AND a.plan_digest=r.plan_digest AND
				a.human_id=? AND a.status='approved' AND a.consumed_at IS NOT NULL AND a.state_revision=? AND a.recovery_epoch=?
			JOIN acknowledgement_proofs proof ON proof.acknowledgement_id=a.acknowledgement_id AND proof.status='approved'
			WHERE r.run_id=? AND r.plan_id=? AND r.plan_digest=? AND r.acknowledgement_id=? AND r.executor_mode='central' AND
				r.status='running' AND r.state_revision=? AND r.recovery_epoch=?`, request.StepID, request.Catalog.RepositoryID,
			catalogDigest, request.Catalog.SourceCoverageDigest, request.ExecutorLeaseID, request.ExecutorLeaseID,
			request.Catalog.RepositoryID, request.Expected.RecoveryEpoch, request.HumanID,
			request.Expected.StateRevision, request.Expected.RecoveryEpoch, request.RunID, request.PlanID, request.PlanDigest,
			request.AcknowledgementID, request.Expected.StateRevision, request.Expected.RecoveryEpoch).Scan(&leaseExpires)
		if errors.Is(err, sql.ErrNoRows) || !retirementDeadlineCurrent(leaseExpires, nowTime) {
			return newStoreError(generated.ErrorCodeAuthorizationDenied, "local-retention-lock-human-run", false, nil)
		}
		if err != nil {
			return err
		}
		for _, lock := range request.Catalog.Locks {
			var count int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM recovery_points WHERE point_id=? AND repository_id=? AND repository_class=? AND recovery_epoch=?`,
				lock.PointID, request.Catalog.RepositoryID, request.Catalog.RepositoryClass, request.Catalog.RecoveryEpoch).Scan(&count); err != nil {
				return err
			}
			if count != 1 {
				return newStoreError(generated.ErrorCodePrerequisiteBlocked, "local-retention-lock-unknown-point", false, nil)
			}
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO backup_retention_lock_catalog_activations(activation_id,repository_id,repository_class,catalog_digest,source_coverage_digest,canonical_json,declaration_id,declaration_revision,plan_id,plan_digest,run_id,step_id,acknowledgement_id,human_id,state_revision,recovery_epoch,activated_at)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, activationID, request.Catalog.RepositoryID, request.Catalog.RepositoryClass, catalogDigest,
			request.Catalog.SourceCoverageDigest, string(canonical), plan.DeclarationID, request.Catalog.Revision, request.PlanID, request.PlanDigest,
			request.RunID, request.StepID, request.AcknowledgementID, request.HumanID, request.Expected.StateRevision, request.Expected.RecoveryEpoch, now)
		return err
	})
	if err != nil {
		return "", err
	}
	if !result.Created {
		var storedDigest string
		if err := repository.store.Read(ctx, func(tx ReadTx) error {
			return tx.queryRow(ctx, `SELECT catalog_digest FROM backup_retention_lock_catalog_activations WHERE activation_id=?`, activationID).Scan(&storedDigest)
		}); err != nil || storedDigest != catalogDigest {
			return "", newStoreError(generated.ErrorCodeIntegrityFailure, "local-retention-lock-replay", false, err)
		}
	}
	return activationID, nil
}
