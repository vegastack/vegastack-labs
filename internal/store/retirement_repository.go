package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/backupidentity"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/stateexport"
)

// LocalRetirementRepository records only inert proposals. No method here
// grants a retention lease or exposes retained-object mutation authority.
type LocalRetirementRepository struct{ store *Store }

func NewLocalRetirementRepository(store *Store) *LocalRetirementRepository {
	return &LocalRetirementRepository{store: store}
}

type LocalRetirementTarget struct {
	PointID, SnapshotID, ManifestDigest, InventoryDigest, DependencyDigest string
}

type LocalRetirementSurvivor struct {
	PointID, SnapshotID, ManifestDigest, InventoryDigest, DependencyDigest, ProofDigest string
}

type LocalRetirementStageRequest struct {
	PlanID, PlanDigest, RepositoryID, RepositoryClass                      string
	CatalogDigest, ExpectedInventoryDigest, SelectionDigest                string
	LockCatalogDigest, SourceCoverageDigest                                string
	LockCatalogSequence                                                    int64
	Targets                                                                []LocalRetirementTarget
	Survivors                                                              []LocalRetirementSurvivor
	SourceRevision, StateRevision, RecoveryEpoch                           int64
	ExpectedReclaimBytes, MaxWorkObjects, MaxMutationBytes, MaxRepackBytes int64
	Attribution                                                            audit.Attribution
}

type LocalRetirementIntent struct {
	IntentID  string
	Request   LocalRetirementStageRequest
	CreatedAt string
}

type retirementSelectionPayload struct {
	RepositoryID, RepositoryClass, CatalogDigest, ExpectedInventoryDigest  string
	LockCatalogDigest, SourceCoverageDigest                                string
	LockCatalogSequence                                                    int64
	Targets                                                                []LocalRetirementTarget
	Survivors                                                              []LocalRetirementSurvivor
	SourceRevision, StateRevision, RecoveryEpoch                           int64
	ExpectedReclaimBytes, MaxWorkObjects, MaxMutationBytes, MaxRepackBytes int64
}

func retirementDeadlineCurrent(raw string, now time.Time) bool {
	deadline, err := time.Parse(time.RFC3339Nano, raw)
	return err == nil && now.Before(deadline)
}

func localRepositoryPlanTargetDigest(repositoryID string) (string, error) {
	_, sum, err := stateexport.CanonicalJSON([]string{repositoryID})
	if err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func validRetirementID(value string) bool {
	if len(value) < 1 || len(value) > 128 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, char := range value[1:] {
		if char < 'a' || char > 'z' {
			if char < '0' || char > '9' {
				if char != '-' && char != '_' && char != '.' && char != ':' {
					return false
				}
			}
		}
	}
	return true
}

func validRetirementSnapshotID(value string) bool {
	return len(value) == 64 && validBackupDigest("sha256:"+value)
}

func canonicalRetirementSelection(request LocalRetirementStageRequest) ([]byte, string, error) {
	invalid := func() ([]byte, string, error) {
		return nil, "", newStoreError(generated.ErrorCodeInputInvalid, "local-retirement-selection", false, nil)
	}
	if request.RepositoryClass != "standard" && request.RepositoryClass != "critical" {
		return invalid()
	}
	wantRepository := backupidentity.StandardRepository
	if request.RepositoryClass == "critical" {
		wantRepository = backupidentity.CriticalRepository
	}
	if request.RepositoryID != wantRepository || !validBackupDigest(request.CatalogDigest) || !validBackupDigest(request.ExpectedInventoryDigest) ||
		!validBackupDigest(request.LockCatalogDigest) || !validBackupDigest(request.SourceCoverageDigest) || request.LockCatalogSequence < 1 ||
		request.SourceRevision < 1 || request.StateRevision < 1 || request.RecoveryEpoch < 0 || request.ExpectedReclaimBytes < 0 ||
		request.MaxWorkObjects < 1 || request.MaxMutationBytes < 1 || request.MaxRepackBytes < 1 ||
		len(request.Targets) < 1 || len(request.Survivors) < 1 || len(request.Targets)+len(request.Survivors) > 256 {
		return invalid()
	}
	targets := append([]LocalRetirementTarget(nil), request.Targets...)
	survivors := append([]LocalRetirementSurvivor(nil), request.Survivors...)
	sort.Slice(targets, func(left, right int) bool { return targets[left].PointID < targets[right].PointID })
	sort.Slice(survivors, func(left, right int) bool { return survivors[left].PointID < survivors[right].PointID })
	points, snapshots := make(map[string]bool), make(map[string]bool)
	for _, target := range targets {
		if !validRetirementID(target.PointID) || !validRetirementSnapshotID(target.SnapshotID) ||
			!validBackupDigest(target.ManifestDigest) || !validBackupDigest(target.InventoryDigest) || !validBackupDigest(target.DependencyDigest) || points[target.PointID] || snapshots[target.SnapshotID] {
			return invalid()
		}
		points[target.PointID], snapshots[target.SnapshotID] = true, true
	}
	for _, survivor := range survivors {
		if !validRetirementID(survivor.PointID) || !validRetirementSnapshotID(survivor.SnapshotID) ||
			!validBackupDigest(survivor.ManifestDigest) || !validBackupDigest(survivor.InventoryDigest) || !validBackupDigest(survivor.DependencyDigest) || !validBackupDigest(survivor.ProofDigest) ||
			points[survivor.PointID] || snapshots[survivor.SnapshotID] {
			return invalid()
		}
		points[survivor.PointID], snapshots[survivor.SnapshotID] = true, true
	}
	payload := retirementSelectionPayload{RepositoryID: request.RepositoryID, RepositoryClass: request.RepositoryClass,
		CatalogDigest: request.CatalogDigest, ExpectedInventoryDigest: request.ExpectedInventoryDigest,
		LockCatalogDigest: request.LockCatalogDigest, SourceCoverageDigest: request.SourceCoverageDigest, LockCatalogSequence: request.LockCatalogSequence,
		Targets: targets, Survivors: survivors, SourceRevision: request.SourceRevision, StateRevision: request.StateRevision,
		RecoveryEpoch: request.RecoveryEpoch, ExpectedReclaimBytes: request.ExpectedReclaimBytes, MaxWorkObjects: request.MaxWorkObjects,
		MaxMutationBytes: request.MaxMutationBytes, MaxRepackBytes: request.MaxRepackBytes}
	canonical, err := json.Marshal(payload)
	if err != nil || len(canonical) > 1048576 {
		return invalid()
	}
	sum := sha256.Sum256(append([]byte("local-retirement-selection-v1\x00"), canonical...))
	return canonical, "sha256:" + hex.EncodeToString(sum[:]), nil
}

// StageLocalRetirement binds an inert proposal to one current, stored,
// destructive human plan. It does not advance desired state or authorize work.
func (repository *LocalRetirementRepository) StageLocalRetirement(ctx context.Context, request LocalRetirementStageRequest) (LocalRetirementIntent, error) {
	var zero LocalRetirementIntent
	if repository == nil || repository.store == nil || !validRetirementID(request.PlanID) || !validBackupDigest(request.PlanDigest) ||
		request.Attribution.AuthenticatedPrincipalID == "" || request.Attribution.AuthenticatedPrincipalMethod == "" {
		return zero, newStoreError(generated.ErrorCodeInputInvalid, "local-retirement-intent", false, nil)
	}
	selectionJSON, digest, err := canonicalRetirementSelection(request)
	if err != nil || request.SelectionDigest != digest {
		return zero, newStoreError(generated.ErrorCodeInputInvalid, "local-retirement-selection-digest", false, err)
	}
	targetDigest, err := localRepositoryPlanTargetDigest(request.RepositoryID)
	if err != nil {
		return zero, newStoreError(generated.ErrorCodeInputInvalid, "local-retirement-plan-target", false, err)
	}
	canonical, err := json.Marshal(struct {
		PlanID, PlanDigest, SelectionDigest string
		Selection                           json.RawMessage
		Attribution                         audit.Attribution
	}{request.PlanID, request.PlanDigest, digest, selectionJSON, request.Attribution})
	if err != nil || len(canonical) > 1048576 {
		return zero, newStoreError(generated.ErrorCodeInputInvalid, "local-retirement-intent", false, err)
	}
	requestSum := sha256.Sum256(canonical)
	requestDigest := "sha256:" + hex.EncodeToString(requestSum[:])
	intentID := "retirement-" + hex.EncodeToString(requestSum[:16])
	key := audit.IntentKey{Scope: "local-retirement-intent", KeyDigest: audit.Fingerprint(digestParts("local-retirement-intent", request.PlanID)), RequestDigest: audit.Fingerprint(requestDigest)}
	after := audit.Fingerprint(digest)
	event := audit.EventDraft{Type: "backup.retirement-intent-staged", CorrelationID: intentID, Attribution: request.Attribution,
		Target: audit.Target{Kind: "backup-retirement-intent", ID: intentID}, After: &after}
	if audit.ValidateIntentKey(key) != nil || audit.ValidateEventDraft(event) != nil {
		return zero, newStoreError(generated.ErrorCodeInputInvalid, "local-retirement-audit", false, nil)
	}
	nowTime := repository.store.config.Clock().UTC()
	now := nowTime.Truncate(time.Second).Format(time.RFC3339)
	intent, err := repository.store.executeAuditIntent(ctx, intentRequest{Expected: &RevisionToken{StateRevision: request.StateRevision, RecoveryEpoch: request.RecoveryEpoch}, Idempotency: key, Event: event}, false, func(ctx context.Context, tx *sql.Tx) error {
		var canonicalPlan []byte
		var readable, expires string
		if err := tx.QueryRowContext(ctx, `SELECT p.canonical_bytes,p.readable_plan,p.expires_at FROM immutable_plans p JOIN declaration_revisions d ON d.declaration_id=p.declaration_id AND d.declaration_revision=p.declaration_revision WHERE p.plan_id=? AND p.plan_digest=? AND p.state_revision=? AND p.recovery_epoch=? AND d.declaration_type='backup.retirement' AND d.status='committed'`,
			request.PlanID, request.PlanDigest, request.StateRevision, request.RecoveryEpoch).Scan(&canonicalPlan, &readable, &expires); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return newStoreError(generated.ErrorCodePrerequisiteBlocked, "local-retirement-plan", false, nil)
			}
			return err
		}
		var plan generated.Plan
		if !decodeStoredPlan(canonicalPlan, readable, &plan) {
			return newStoreError(generated.ErrorCodePrerequisiteBlocked, "local-retirement-plan", false, nil)
		}
		var selectionExtension, credentialExtension string
		for _, extension := range plan.Extensions {
			switch extension.Name {
			case "x-backup-local-retirement":
				selectionExtension = extension.ValueDigest
			case "x-credential-bindings":
				credentialExtension = extension.ValueDigest
			}
		}
		if plan.Risk != "destructive" || plan.AuthorizationBranch != "human" || plan.ExecutorMode != "central" ||
			plan.Binding.DeclarationRevision != request.SourceRevision || plan.Binding.TargetDigest != targetDigest || len(plan.Operations) != 1 ||
			plan.Operations[0].OperationType != "backup.local.retire" || plan.Operations[0].AdapterID != "local.retention" ||
			plan.Operations[0].TargetID != request.RepositoryID || len(plan.Extensions) != 2 || selectionExtension != digest || credentialExtension == "" || plan.Operations[0].InputDigest != credentialExtension ||
			plan.Operations[0].ArtifactDigest != request.ExpectedInventoryDigest || !retirementDeadlineCurrent(expires, nowTime) {
			return newStoreError(generated.ErrorCodePrerequisiteBlocked, "local-retirement-plan", false, nil)
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO backup_retirement_intents(intent_id,plan_id,plan_digest,repository_id,repository_class,catalog_digest,expected_inventory_digest,lock_catalog_digest,source_coverage_digest,lock_catalog_sequence,selection_digest,canonical_json,target_count,survivor_count,source_revision,state_revision,recovery_epoch,expected_reclaim_bytes,max_work_objects,max_mutation_bytes,max_repack_bytes,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			intentID, request.PlanID, request.PlanDigest, request.RepositoryID, request.RepositoryClass, request.CatalogDigest, request.ExpectedInventoryDigest, request.LockCatalogDigest, request.SourceCoverageDigest, request.LockCatalogSequence, digest, string(canonical), len(request.Targets), len(request.Survivors), request.SourceRevision, request.StateRevision, request.RecoveryEpoch, request.ExpectedReclaimBytes, request.MaxWorkObjects, request.MaxMutationBytes, request.MaxRepackBytes, now)
		return err
	})
	if err != nil {
		return zero, err
	}
	createdAt := now
	if !intent.Created {
		var storedDigest, storedCanonical string
		if err := repository.store.Read(ctx, func(tx ReadTx) error {
			return tx.queryRow(ctx, `SELECT selection_digest,canonical_json,created_at FROM backup_retirement_intents WHERE intent_id=?`, intentID).Scan(&storedDigest, &storedCanonical, &createdAt)
		}); err != nil || storedDigest != digest || storedCanonical != string(canonical) {
			return zero, newStoreError(generated.ErrorCodeIntegrityFailure, "local-retirement-replay", false, err)
		}
	}
	request.Targets = append([]LocalRetirementTarget(nil), request.Targets...)
	request.Survivors = append([]LocalRetirementSurvivor(nil), request.Survivors...)
	return LocalRetirementIntent{IntentID: intentID, Request: request, CreatedAt: createdAt}, nil
}

// GetLocalRetirementIntentBySelection resolves only an already-staged immutable
// intent. It never stages or claims work.
func (repository *LocalRetirementRepository) GetLocalRetirementIntentBySelection(ctx context.Context, selectionDigest string) (LocalRetirementIntent, error) {
	var result LocalRetirementIntent
	if repository == nil || repository.store == nil || !validBackupDigest(selectionDigest) {
		return result, newStoreError(generated.ErrorCodeInputInvalid, "local-retirement-intent-read", false, nil)
	}
	var canonical string
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT intent_id,plan_id,plan_digest,repository_id,repository_class,catalog_digest,expected_inventory_digest,lock_catalog_digest,source_coverage_digest,lock_catalog_sequence,selection_digest,canonical_json,source_revision,state_revision,recovery_epoch,expected_reclaim_bytes,max_work_objects,max_mutation_bytes,max_repack_bytes,created_at FROM backup_retirement_intents WHERE selection_digest=?`, selectionDigest).Scan(
			&result.IntentID, &result.Request.PlanID, &result.Request.PlanDigest, &result.Request.RepositoryID, &result.Request.RepositoryClass,
			&result.Request.CatalogDigest, &result.Request.ExpectedInventoryDigest, &result.Request.LockCatalogDigest, &result.Request.SourceCoverageDigest,
			&result.Request.LockCatalogSequence, &result.Request.SelectionDigest, &canonical, &result.Request.SourceRevision, &result.Request.StateRevision,
			&result.Request.RecoveryEpoch, &result.Request.ExpectedReclaimBytes, &result.Request.MaxWorkObjects, &result.Request.MaxMutationBytes,
			&result.Request.MaxRepackBytes, &result.CreatedAt)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return result, newStoreError(generated.ErrorCodeResourceNotFound, "local-retirement-intent", false, nil)
	}
	if err != nil {
		return result, err
	}
	var stored struct{ Selection retirementSelectionPayload }
	if json.Unmarshal([]byte(canonical), &stored) != nil || stored.Selection.RepositoryID != result.Request.RepositoryID || stored.Selection.RepositoryClass != result.Request.RepositoryClass {
		return LocalRetirementIntent{}, newStoreError(generated.ErrorCodeIntegrityFailure, "local-retirement-intent-read", false, nil)
	}
	result.Request.Targets = stored.Selection.Targets
	result.Request.Survivors = stored.Selection.Survivors
	return result, nil
}
