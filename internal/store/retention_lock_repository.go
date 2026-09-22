package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"

	"github.com/vegastack/vegastack-labs/internal/backupidentity"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

// This closed list names the currently implemented sources of local recovery
// promises. The operator-declared source captures manual recovery/rollback
// promises; future automated producers must join this list before activation.
const localPromiseSourceClosure = "local-retention-promise-sources-v1\x00operator-declared"

func LocalPromiseSourceCoverageDigest() string {
	sum := sha256.Sum256([]byte(localPromiseSourceClosure))
	return "sha256:" + hex.EncodeToString(sum[:])
}

type LocalRetentionLock struct {
	PointID      string `json:"pointId"`
	ReasonDigest string `json:"reasonDigest"`
}

// LocalRetentionLockCatalog is a complete, revisioned declaration payload.
// Complete=false or an absent applied row means unknown, never no promises.
type LocalRetentionLockCatalog struct {
	Schema               string               `json:"schema"`
	SchemaVersion        string               `json:"schemaVersion"`
	RepositoryID         string               `json:"repositoryId"`
	RepositoryClass      string               `json:"repositoryClass"`
	SourceCoverageDigest string               `json:"sourceCoverageDigest"`
	RecoveryEpoch        int64                `json:"recoveryEpoch"`
	Revision             int64                `json:"revision"`
	Complete             bool                 `json:"complete"`
	Locks                []LocalRetentionLock `json:"locks"`
}

type AppliedLocalRetentionLocks struct {
	ActivationID, CatalogDigest string
	Sequence                    int64
	Catalog                     LocalRetentionLockCatalog
}

func canonicalLocalRetentionLockCatalog(value LocalRetentionLockCatalog) ([]byte, string, error) {
	invalid := func() ([]byte, string, error) {
		return nil, "", newStoreError(generated.ErrorCodeInputInvalid, "local-retention-lock-catalog", false, nil)
	}
	if value.Schema != "vegastack-labs.dev/local-retention-lock-catalog" || value.SchemaVersion != "1.0.0" ||
		value.RecoveryEpoch < 0 || value.Revision < 1 || !value.Complete || value.SourceCoverageDigest != LocalPromiseSourceCoverageDigest() ||
		len(value.Locks) > 256 || (value.RepositoryClass != "standard" && value.RepositoryClass != "critical") {
		return invalid()
	}
	wantRepository := backupidentity.StandardRepository
	if value.RepositoryClass == "critical" {
		wantRepository = backupidentity.CriticalRepository
	}
	if value.RepositoryID != wantRepository {
		return invalid()
	}
	value.Locks = append([]LocalRetentionLock(nil), value.Locks...)
	sort.Slice(value.Locks, func(i, j int) bool { return value.Locks[i].PointID < value.Locks[j].PointID })
	for index, lock := range value.Locks {
		if !validRetirementID(lock.PointID) || !validBackupDigest(lock.ReasonDigest) ||
			(index > 0 && value.Locks[index-1].PointID == lock.PointID) {
			return invalid()
		}
	}
	if value.Locks == nil {
		value.Locks = []LocalRetentionLock{}
	}
	canonical, err := json.Marshal(value)
	if err != nil || len(canonical) > 1048576 {
		return invalid()
	}
	sum := sha256.Sum256(append([]byte("local-retention-lock-catalog-v1\x00"), canonical...))
	return canonical, "sha256:" + hex.EncodeToString(sum[:]), nil
}

// CurrentAppliedLocalRetentionLocks reads only a complete, current-epoch
// activation. Its absence is a prerequisite blocker for every retirement.
func (repository *LocalRetirementRepository) CurrentAppliedLocalRetentionLocks(ctx context.Context, class string, epoch int64) (AppliedLocalRetentionLocks, error) {
	var result AppliedLocalRetentionLocks
	if repository == nil || repository.store == nil || epoch < 0 || (class != "standard" && class != "critical") {
		return result, newStoreError(generated.ErrorCodeInputInvalid, "local-retention-lock-catalog", false, nil)
	}
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		var canonical, coverage, repositoryID string
		var planBytes []byte
		var currentEpoch, stateRevision, activationStateRevision int64
		if err := tx.queryRow(ctx, `SELECT m.recovery_epoch,m.state_revision FROM system_meta m WHERE m.id=1`).Scan(&currentEpoch, &stateRevision); err != nil {
			return err
		}
		if currentEpoch != epoch {
			return newStoreError(generated.ErrorCodeRecoveryEpochMismatch, "local-retention-lock-catalog", false, nil)
		}
		if err := tx.queryRow(ctx, `SELECT a.activation_id,a.activation_sequence,a.catalog_digest,a.canonical_json,a.source_coverage_digest,a.repository_id,a.state_revision,p.canonical_bytes
			FROM (SELECT * FROM backup_retention_lock_catalog_activations WHERE repository_class=? AND recovery_epoch=? ORDER BY activation_sequence DESC LIMIT 1) a
			JOIN immutable_plans p ON p.plan_id=a.plan_id AND p.plan_digest=a.plan_digest AND p.declaration_id=a.declaration_id AND p.declaration_revision=a.declaration_revision
			JOIN declaration_revisions d ON d.declaration_id=a.declaration_id AND d.declaration_revision=a.declaration_revision AND d.declaration_type='backup.retention-locks' AND d.status='committed'
			JOIN plan_runs r ON r.run_id=a.run_id AND r.plan_id=a.plan_id AND r.plan_digest=a.plan_digest AND r.acknowledgement_id=a.acknowledgement_id AND r.status='succeeded'
			JOIN plan_run_steps s ON s.step_id=a.step_id AND s.run_id=a.run_id AND s.status='succeeded' AND s.effect_state='verified'
			JOIN acknowledgement_requests ar ON ar.acknowledgement_id=a.acknowledgement_id AND ar.plan_id=a.plan_id AND ar.plan_digest=a.plan_digest AND ar.human_id=a.human_id AND ar.status='approved'
			JOIN acknowledgement_proofs ap ON ap.acknowledgement_id=a.acknowledgement_id AND ap.status='approved'`, class, epoch).
			Scan(&result.ActivationID, &result.Sequence, &result.CatalogDigest, &canonical, &coverage, &repositoryID, &activationStateRevision, &planBytes); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return newStoreError(generated.ErrorCodePrerequisiteBlocked, "local-retention-lock-catalog-missing", false, nil)
			}
			return err
		}
		if json.Unmarshal([]byte(canonical), &result.Catalog) != nil {
			return newStoreError(generated.ErrorCodeIntegrityFailure, "local-retention-lock-catalog", false, nil)
		}
		var plan generated.Plan
		targetDigest, targetErr := localRepositoryPlanTargetDigest(repositoryID)
		if json.Unmarshal(planBytes, &plan) != nil || plan.AuthorizationBranch != "human" || plan.Risk != "destructive" || plan.ExecutorMode != "central" ||
			targetErr != nil || plan.Binding.TargetDigest != targetDigest || plan.Binding.RecoveryEpoch != epoch || len(plan.Operations) != 1 ||
			plan.Operations[0].OperationType != "backup.retention-locks.activate" || plan.Operations[0].AdapterID != "core.retention-locks" ||
			plan.Operations[0].TargetID != repositoryID || plan.Operations[0].InputDigest != result.CatalogDigest ||
			plan.Operations[0].ArtifactDigest != coverage || plan.Binding.StateRevision != activationStateRevision ||
			plan.Binding.DeclarationRevision != result.Catalog.Revision {
			return newStoreError(generated.ErrorCodePrerequisiteBlocked, "local-retention-lock-catalog-plan", false, nil)
		}
		remarshal, digest, err := canonicalLocalRetentionLockCatalog(result.Catalog)
		if err != nil || string(remarshal) != canonical || digest != result.CatalogDigest || coverage != result.Catalog.SourceCoverageDigest ||
			result.Catalog.RepositoryClass != class || result.Catalog.RepositoryID != repositoryID || result.Catalog.RecoveryEpoch != epoch ||
			result.Sequence < 1 || activationStateRevision > stateRevision {
			return newStoreError(generated.ErrorCodePrerequisiteBlocked, "local-retention-lock-catalog-stale", false, nil)
		}
		for _, lock := range result.Catalog.Locks {
			var count int
			if err := tx.queryRow(ctx, `SELECT COUNT(*) FROM recovery_points WHERE point_id=? AND repository_id=? AND repository_class=? AND recovery_epoch=?`,
				lock.PointID, repositoryID, class, epoch).Scan(&count); err != nil {
				return err
			}
			if count != 1 {
				return newStoreError(generated.ErrorCodePrerequisiteBlocked, "local-retention-lock-unknown-point", false, nil)
			}
		}
		return nil
	})
	return result, err
}
