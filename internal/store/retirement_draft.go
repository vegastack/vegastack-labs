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
	"github.com/vegastack/vegastack-labs/internal/generated"
)

type LocalRetirementDraftInput struct {
	PointID, SnapshotID, RepositoryID                              string
	ManifestDigest, DependencyDigest, InventoryDigest, ProofDigest string
	CreatedAt                                                      time.Time
	Bytes, SourceRevision, RecoveryEpoch                           int64
}

type LocalRetirementDraftSources struct {
	Points                                                               []LocalRetirementDraftInput
	LastGoodIDs                                                          []string
	Objects                                                              []ExpectedObjectRow
	Locks                                                                AppliedLocalRetentionLocks
	StateRevision, RecoveryEpoch                                         int64
	CapacityTotalBytes, CapacityAvailableBytes, CapacityQuarantinedBytes int64
	ExpectedGrowthBytes                                                  int64
}

type localRetirementCurrentSuccessor struct {
	Digest, InventoryDigest string
	StateRevision           int64
	RecordedAt              time.Time
	Survivors               []LocalRetirementSurvivor
	Objects                 []ExpectedObjectRow
	RetiredPointIDs         map[string]bool
}

func isPostSuccessorRecoveryPoint(successor *localRetirementCurrentSuccessor, pointID, verificationSuccessorDigest string, verificationState int64, pointCreatedAt time.Time) bool {
	return successor != nil && !successor.RetiredPointIDs[pointID] && verificationSuccessorDigest == "" &&
		(verificationState > successor.StateRevision || verificationState == successor.StateRevision && pointCreatedAt.After(successor.RecordedAt))
}

func loadLocalRetirementCurrentPointIDs(ctx context.Context, tx ReadTx, class string, epoch int64) (map[string]bool, error) {
	successor, err := loadLocalRetirementCurrentSuccessor(ctx, tx, class, epoch)
	if err != nil {
		return nil, err
	}
	rows, err := tx.query(ctx, `SELECT p.point_id,p.snapshot_id,p.manifest_digest,p.inventory_digest,p.manifest_json,p.created_at,COALESCE(v.successor_generation_digest,''),v.state_revision
		FROM recovery_points p JOIN backup_local_verifications v ON v.verification_id=(SELECT verification_id FROM backup_local_verifications WHERE point_id=p.point_id AND status='local-verified' AND proof_class='live' ORDER BY state_revision DESC,created_at DESC,verification_id DESC LIMIT 1)
		WHERE p.repository_class=? AND p.recovery_epoch=?`, class, epoch)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[string]bool{}
	survivors := map[string]LocalRetirementSurvivor{}
	if successor != nil {
		for _, survivor := range successor.Survivors {
			survivors[survivor.PointID] = survivor
		}
	}
	for rows.Next() {
		var pointID, snapshotID, manifestDigest, inventoryDigest, manifestJSON, created, successorDigest string
		var verificationState int64
		if err := rows.Scan(&pointID, &snapshotID, &manifestDigest, &inventoryDigest, &manifestJSON, &created, &successorDigest, &verificationState); err != nil {
			return nil, err
		}
		if successor == nil {
			result[pointID] = true
			continue
		}
		createdAt, parseErr := time.Parse(time.RFC3339, created)
		var manifest pendingCreationManifest
		if parseErr != nil || json.Unmarshal([]byte(manifestJSON), &manifest) != nil {
			return nil, newStoreError(generated.ErrorCodeIntegrityFailure, "local-retirement-current-points", false, parseErr)
		}
		if expected, ok := survivors[pointID]; ok {
			if successorDigest != successor.Digest || snapshotID != expected.SnapshotID || manifestDigest != expected.ManifestDigest || inventoryDigest != expected.InventoryDigest || manifest.DependencyInventoryDigest != expected.DependencyDigest {
				return nil, newStoreError(generated.ErrorCodeIntegrityFailure, "local-retirement-successor-source", false, nil)
			}
			result[pointID] = true
		} else if isPostSuccessorRecoveryPoint(successor, pointID, successorDigest, verificationState, createdAt) {
			result[pointID] = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if successor != nil && len(result) < len(successor.Survivors) {
		return nil, newStoreError(generated.ErrorCodePrerequisiteBlocked, "local-retirement-successor-source", false, nil)
	}
	return result, nil
}

func loadLocalRetirementCurrentSuccessor(ctx context.Context, tx ReadTx, class string, epoch int64) (*localRetirementCurrentSuccessor, error) {
	rows, err := tx.query(ctx, `SELECT g.intent_id,g.generation_sequence,g.parent_generation_digest,g.generation_digest,g.predecessor_inventory_digest,g.successor_inventory_digest,g.journal_digest,g.survivor_proof_digest,g.survivor_count,g.canonical_json,g.state_revision,g.recorded_at,i.canonical_json
		FROM backup_retirement_successor_generations g JOIN backup_retirement_intents i ON i.intent_id=g.intent_id
		WHERE g.repository_class=? AND g.recovery_epoch=? AND EXISTS (
			SELECT 1 FROM backup_retirement_receipts r
			WHERE r.intent_id=g.intent_id AND r.status='verified'
			AND r.journal_digest=g.journal_digest AND r.proof_digest=g.survivor_proof_digest
		)
		ORDER BY g.generation_sequence`, class, epoch)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var latest *localRetirementCurrentSuccessor
	var priorDigest, priorInventory string
	var count, sequence int64
	retiredPointIDs := map[string]bool{}
	for rows.Next() {
		var intentID, digest, predecessor, inventory, journal, proof, canonical, recorded, intentCanonical string
		var parent sql.NullString
		var survivorCount, state int64
		if err := rows.Scan(&intentID, &sequence, &parent, &digest, &predecessor, &inventory, &journal, &proof, &survivorCount, &canonical, &state, &recorded, &intentCanonical); err != nil {
			return nil, err
		}
		count++
		if sequence != count || (count == 1 && parent.Valid) || (count > 1 && (!parent.Valid || parent.String != priorDigest || predecessor != priorInventory)) {
			return nil, newStoreError(generated.ErrorCodeIntegrityFailure, "local-retirement-successor-chain", false, nil)
		}
		var payload localRetirementSuccessorPayload
		var intent struct {
			Selection retirementSelectionPayload `json:"selection"`
		}
		sum := sha256.Sum256([]byte(canonical))
		if json.Unmarshal([]byte(canonical), &payload) != nil || json.Unmarshal([]byte(intentCanonical), &intent) != nil || payload.IntentID != intentID || payload.InventoryDigest != inventory || payload.JournalDigest != journal || payload.ProofDigest != proof || payload.Epoch != epoch ||
			"sha256:"+hex.EncodeToString(sum[:]) != digest || int64(len(payload.Survivors)) != survivorCount || pendingInventoryDigest(payload.Objects) != inventory {
			return nil, newStoreError(generated.ErrorCodeIntegrityFailure, "local-retirement-successor-chain", false, nil)
		}
		for _, target := range intent.Selection.Targets {
			if !validRetirementID(target.PointID) || retiredPointIDs[target.PointID] {
				return nil, newStoreError(generated.ErrorCodeIntegrityFailure, "local-retirement-successor-chain", false, nil)
			}
			retiredPointIDs[target.PointID] = true
		}
		seenPoints, seenObjects := map[string]bool{}, map[string]bool{}
		for _, survivor := range payload.Survivors {
			if !validRetirementID(survivor.PointID) || !validRetirementSnapshotID(survivor.SnapshotID) || !validBackupDigest(survivor.ManifestDigest) || !validBackupDigest(survivor.InventoryDigest) || !validBackupDigest(survivor.DependencyDigest) || !validBackupDigest(survivor.ProofDigest) || seenPoints[survivor.PointID] {
				return nil, newStoreError(generated.ErrorCodeIntegrityFailure, "local-retirement-successor-chain", false, nil)
			}
			seenPoints[survivor.PointID] = true
		}
		for _, object := range payload.Objects {
			key := object.Type + "\x00" + object.Name
			if !validPendingObject(object) || seenObjects[key] {
				return nil, newStoreError(generated.ErrorCodeIntegrityFailure, "local-retirement-successor-chain", false, nil)
			}
			seenObjects[key] = true
		}
		recordedAt, parseErr := time.Parse(time.RFC3339, recorded)
		if parseErr != nil {
			return nil, newStoreError(generated.ErrorCodeIntegrityFailure, "local-retirement-successor-chain", false, parseErr)
		}
		latest = &localRetirementCurrentSuccessor{Digest: digest, InventoryDigest: inventory, StateRevision: state, RecordedAt: recordedAt,
			Survivors: append([]LocalRetirementSurvivor(nil), payload.Survivors...), Objects: append([]ExpectedObjectRow(nil), payload.Objects...), RetiredPointIDs: retiredPointIDs}
		priorDigest, priorInventory = digest, inventory
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var total int64
	if err := tx.queryRow(ctx, `SELECT COUNT(*) FROM backup_retirement_successor_generations WHERE repository_class=? AND recovery_epoch=?`, class, epoch).Scan(&total); err != nil {
		return nil, err
	}
	if total != count {
		return nil, newStoreError(generated.ErrorCodeIntegrityFailure, "local-retirement-successor-chain", false, nil)
	}
	return latest, nil
}

// LoadLocalRetirementDraftSources reads only current authoritative rows. Every
// point must have a live complete verification; an unverified survivor cannot
// be hidden by caller input because callers never supply the point list.
func (repository *LocalRetirementRepository) LoadLocalRetirementDraftSources(ctx context.Context, class string, epoch int64) (LocalRetirementDraftSources, error) {
	var result LocalRetirementDraftSources
	if repository == nil || repository.store == nil || epoch < 0 || (class != "standard" && class != "critical") {
		return result, newStoreError(generated.ErrorCodeInputInvalid, "local-retirement-draft-sources", false, nil)
	}
	locks, err := repository.CurrentAppliedLocalRetentionLocks(ctx, class, epoch)
	if err != nil {
		return result, err
	}
	err = repository.store.Read(ctx, func(tx ReadTx) error {
		if err := tx.queryRow(ctx, `SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&result.StateRevision, &result.RecoveryEpoch); err != nil {
			return err
		}
		if result.RecoveryEpoch != epoch {
			return newStoreError(generated.ErrorCodeRecoveryEpochMismatch, "local-retirement-draft-sources", false, nil)
		}
		successor, err := loadLocalRetirementCurrentSuccessor(ctx, tx, class, epoch)
		if err != nil {
			return err
		}
		survivors := map[string]LocalRetirementSurvivor{}
		if successor != nil {
			for _, survivor := range successor.Survivors {
				survivors[survivor.PointID] = survivor
			}
		}
		rows, err := tx.query(ctx, `SELECT p.point_id,p.snapshot_id,p.repository_id,p.manifest_digest,p.inventory_digest,p.object_bytes,p.source_revision,p.recovery_epoch,p.created_at,p.manifest_json,v.proof_digest,COALESCE(v.successor_generation_digest,''),v.state_revision
			FROM recovery_points p JOIN backup_local_verifications v ON v.verification_id=(SELECT verification_id FROM backup_local_verifications WHERE point_id=p.point_id AND status='local-verified' AND proof_class='live' ORDER BY state_revision DESC,created_at DESC,verification_id DESC LIMIT 1)
			WHERE p.repository_class=? AND p.recovery_epoch=? ORDER BY p.point_id`, class, epoch)
		if err != nil {
			return err
		}
		defer rows.Close()
		newestPointID := ""
		var newestPointVerificationRevision int64
		for rows.Next() {
			var point LocalRetirementDraftInput
			var created, manifestJSON, successorDigest string
			var verificationState int64
			if err := rows.Scan(&point.PointID, &point.SnapshotID, &point.RepositoryID, &point.ManifestDigest, &point.InventoryDigest, &point.Bytes, &point.SourceRevision, &point.RecoveryEpoch, &created, &manifestJSON, &point.ProofDigest, &successorDigest, &verificationState); err != nil {
				return err
			}
			var manifest pendingCreationManifest
			if json.Unmarshal([]byte(manifestJSON), &manifest) != nil || manifest.PointID != point.PointID || manifest.DependencyInventoryDigest == "" {
				return newStoreError(generated.ErrorCodeIntegrityFailure, "local-retirement-draft-manifest", false, nil)
			}
			point.DependencyDigest = manifest.DependencyInventoryDigest
			point.CreatedAt, err = time.Parse(time.RFC3339, created)
			if err != nil {
				return newStoreError(generated.ErrorCodeIntegrityFailure, "local-retirement-draft-created", false, err)
			}
			if successor != nil {
				expected, current := survivors[point.PointID]
				if !current {
					if !isPostSuccessorRecoveryPoint(successor, point.PointID, successorDigest, verificationState, point.CreatedAt) {
						continue
					}
					if verificationState > newestPointVerificationRevision || (verificationState == newestPointVerificationRevision && point.PointID > newestPointID) {
						newestPointID, newestPointVerificationRevision = point.PointID, verificationState
					}
				} else if successorDigest != successor.Digest || point.SnapshotID != expected.SnapshotID || point.ManifestDigest != expected.ManifestDigest || point.InventoryDigest != expected.InventoryDigest || point.DependencyDigest != expected.DependencyDigest {
					return newStoreError(generated.ErrorCodeIntegrityFailure, "local-retirement-successor-source", false, nil)
				}
			}
			result.Points = append(result.Points, point)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if successor == nil {
			var total int
			if err := tx.queryRow(ctx, `SELECT COUNT(*) FROM recovery_points WHERE repository_class=? AND recovery_epoch=?`, class, epoch).Scan(&total); err != nil {
				return err
			}
			if total == 0 || total != len(result.Points) {
				return newStoreError(generated.ErrorCodePrerequisiteBlocked, "local-retirement-unverified-point", false, nil)
			}
		} else if len(result.Points) < len(successor.Survivors) {
			return newStoreError(generated.ErrorCodePrerequisiteBlocked, "local-retirement-successor-source", false, nil)
		}
		last, err := tx.query(ctx, `SELECT point_id FROM backup_local_last_good WHERE repository_class=? AND recovery_epoch=?`, class, epoch)
		if err != nil {
			return err
		}
		for last.Next() {
			var id string
			if err := last.Scan(&id); err != nil {
				last.Close()
				return err
			}
			result.LastGoodIDs = append(result.LastGoodIDs, id)
		}
		if err := last.Err(); err != nil {
			last.Close()
			return err
		}
		last.Close()
		if successor != nil && newestPointID == "" {
			result.Objects = append([]ExpectedObjectRow(nil), successor.Objects...)
			if pendingInventoryDigest(result.Objects) != successor.InventoryDigest {
				return newStoreError(generated.ErrorCodeIntegrityFailure, "local-retirement-successor-inventory", false, nil)
			}
		} else {
			query := `SELECT o.object_type,o.object_name,o.object_bytes,o.object_digest FROM backup_expected_objects o JOIN recovery_points p ON p.point_id=o.point_id WHERE p.repository_class=? AND p.recovery_epoch=? ORDER BY o.object_type,o.object_name,p.point_id`
			args := []any{class, epoch}
			if newestPointID != "" {
				query = `SELECT object_type,object_name,object_bytes,object_digest FROM backup_expected_objects WHERE point_id=? ORDER BY object_type,object_name`
				args = []any{newestPointID}
			}
			objects, err := tx.query(ctx, query, args...)
			if err != nil {
				return err
			}
			seen := map[string]ExpectedObjectRow{}
			for objects.Next() {
				var object ExpectedObjectRow
				if err := objects.Scan(&object.Type, &object.Name, &object.Bytes, &object.Digest); err != nil {
					objects.Close()
					return err
				}
				key := object.Type + "\x00" + object.Name
				if prior, ok := seen[key]; ok && prior != object {
					objects.Close()
					return newStoreError(generated.ErrorCodeIntegrityFailure, "local-retirement-object-conflict", false, nil)
				}
				seen[key] = object
			}
			if err := objects.Err(); err != nil {
				objects.Close()
				return err
			}
			objects.Close()
			for _, object := range seen {
				result.Objects = append(result.Objects, object)
			}
			if newestPointID != "" {
				var expected string
				for _, point := range result.Points {
					if point.PointID == newestPointID {
						expected = point.InventoryDigest
						break
					}
				}
				if pendingInventoryDigest(result.Objects) != expected {
					return newStoreError(generated.ErrorCodeIntegrityFailure, "local-retirement-current-inventory", false, nil)
				}
			}
		}
		sort.Slice(result.Objects, func(i, j int) bool {
			if result.Objects[i].Type == result.Objects[j].Type {
				return result.Objects[i].Name < result.Objects[j].Name
			}
			return result.Objects[i].Type < result.Objects[j].Type
		})
		if len(result.Objects) == 0 {
			return newStoreError(generated.ErrorCodePrerequisiteBlocked, "local-retirement-inventory", false, nil)
		}
		if err := tx.queryRow(ctx, `SELECT total_bytes,available_bytes,quarantined_bytes FROM backup_repository_capacity_observations WHERE repository_class=? AND recovery_epoch=? ORDER BY observed_at DESC,observation_id DESC LIMIT 1`, class, epoch).Scan(&result.CapacityTotalBytes, &result.CapacityAvailableBytes, &result.CapacityQuarantinedBytes); err != nil {
			return newStoreError(generated.ErrorCodePrerequisiteBlocked, "local-retirement-capacity-observation", false, err)
		}
		if err := tx.queryRow(ctx, `SELECT COALESCE(MAX(CAST(json_extract(d.canonical_json,'$.expectedGrowthBytes') AS INTEGER)),0) FROM recovery_points p JOIN backup_policy_drafts d ON d.policy_digest=p.policy_digest AND d.recovery_epoch=p.recovery_epoch WHERE p.repository_class=? AND p.recovery_epoch=?`, class, epoch).Scan(&result.ExpectedGrowthBytes); err != nil || result.ExpectedGrowthBytes < 0 {
			return newStoreError(generated.ErrorCodeIntegrityFailure, "local-retirement-capacity-growth", false, err)
		}
		return nil
	})
	if err != nil {
		return LocalRetirementDraftSources{}, err
	}
	result.Locks = locks
	return result, nil
}

type LocalRetirementDraft struct {
	DraftID, SelectionDigest, DeclarationID           string
	DeclarationRevision, StateRevision, RecoveryEpoch int64
	Selection                                         LocalRetirementStageRequest
	Attribution                                       audit.Attribution
}

type LocalRetirementDraftStoreRequest struct {
	Selection                     LocalRetirementStageRequest
	DeclarationID                 string
	DeclarationRevision           int64
	Expected                      RevisionToken
	IdempotencyKey, RequestDigest string
	Attribution                   audit.Attribution
}

func (repository *LocalRetirementRepository) PutLocalRetirementDraft(ctx context.Context, request LocalRetirementDraftStoreRequest) (LocalRetirementDraft, error) {
	var zero LocalRetirementDraft
	canonical, digest, err := canonicalRetirementSelection(request.Selection)
	if repository == nil || repository.store == nil || err != nil || request.Selection.SelectionDigest != digest || request.DeclarationRevision < 1 || request.Expected.StateRevision < 1 || !validRetirementID(request.DeclarationID) || !validRetirementID(request.IdempotencyKey) || !validBackupDigest(request.RequestDigest) {
		return zero, newStoreError(generated.ErrorCodeInputInvalid, "local-retirement-draft", false, err)
	}
	keySum := sha256.Sum256([]byte(request.IdempotencyKey))
	keyDigest := "sha256:" + hex.EncodeToString(keySum[:])
	draftID := "retirement-draft-" + digest[7:39]
	if existing, lookup := repository.GetLocalRetirementDraftByKey(ctx, keyDigest, request.Expected.RecoveryEpoch); lookup == nil {
		if existing.SelectionDigest != digest || existing.DeclarationID != request.DeclarationID {
			return zero, newStoreError(generated.ErrorCodeStateConflict, "local-retirement-draft-idempotency", false, nil)
		}
		return existing, nil
	} else if Code(lookup) != generated.ErrorCodeResourceNotFound {
		return zero, lookup
	}
	created := repository.store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339)
	payload, err := json.Marshal(struct {
		Selection   json.RawMessage   `json:"selection"`
		Attribution audit.Attribution `json:"attribution"`
	}{canonical, request.Attribution})
	if err != nil {
		return zero, err
	}
	after := audit.Fingerprint(digest)
	event := audit.EventDraft{Type: "backup.retirement-draft-created", CorrelationID: draftID, Attribution: request.Attribution, Target: audit.Target{Kind: "backup-retirement-draft", ID: draftID}, After: &after}
	key := audit.IntentKey{Scope: "local-retirement-draft", KeyDigest: audit.Fingerprint(keyDigest), RequestDigest: audit.Fingerprint(request.RequestDigest)}
	intent, err := repository.store.writeIntent(ctx, intentRequest{Expected: &request.Expected, Idempotency: key, Event: event}, func(ctx context.Context, tx *sql.Tx) error {
		var kind, status string
		var state, epoch int64
		if err := tx.QueryRowContext(ctx, `SELECT declaration_type,status,state_revision,recovery_epoch FROM declaration_revisions WHERE declaration_id=? AND declaration_revision=?`, request.DeclarationID, request.DeclarationRevision).Scan(&kind, &status, &state, &epoch); err != nil {
			return err
		}
		if kind != "backup.retirement" || status != "draft" || state != request.Expected.StateRevision || epoch != request.Expected.RecoveryEpoch {
			return newStoreError(generated.ErrorCodePrerequisiteBlocked, "local-retirement-declaration", false, nil)
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO backup_retirement_drafts(draft_id,selection_digest,declaration_id,declaration_revision,canonical_json,idempotency_key_digest,state_revision,recovery_epoch,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, draftID, digest, request.DeclarationID, request.DeclarationRevision, string(payload), keyDigest, request.Expected.StateRevision+1, epoch, request.Attribution.AuthenticatedPrincipalID, created)
		return err
	})
	if err != nil {
		return zero, err
	}
	request.Selection.Targets = append([]LocalRetirementTarget(nil), request.Selection.Targets...)
	request.Selection.Survivors = append([]LocalRetirementSurvivor(nil), request.Selection.Survivors...)
	return LocalRetirementDraft{DraftID: draftID, SelectionDigest: digest, DeclarationID: request.DeclarationID, DeclarationRevision: request.DeclarationRevision, StateRevision: intent.Commit.StateRevision, RecoveryEpoch: intent.Commit.RecoveryEpoch, Selection: request.Selection, Attribution: request.Attribution}, nil
}

func (repository *LocalRetirementRepository) GetLocalRetirementDraftBySelection(ctx context.Context, digest string, epoch int64) (LocalRetirementDraft, error) {
	return repository.scanLocalRetirementDraft(ctx, "WHERE selection_digest=? AND recovery_epoch=?", digest, epoch)
}
func (repository *LocalRetirementRepository) GetLocalRetirementDraftByKey(ctx context.Context, key string, epoch int64) (LocalRetirementDraft, error) {
	return repository.scanLocalRetirementDraft(ctx, "WHERE idempotency_key_digest=? AND recovery_epoch=?", key, epoch)
}
func (repository *LocalRetirementRepository) scanLocalRetirementDraft(ctx context.Context, clause string, args ...any) (LocalRetirementDraft, error) {
	var out LocalRetirementDraft
	var canonical string
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT draft_id,selection_digest,declaration_id,declaration_revision,canonical_json,state_revision,recovery_epoch FROM backup_retirement_drafts `+clause, args...).Scan(&out.DraftID, &out.SelectionDigest, &out.DeclarationID, &out.DeclarationRevision, &canonical, &out.StateRevision, &out.RecoveryEpoch)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return out, newStoreError(generated.ErrorCodeResourceNotFound, "local-retirement-draft", false, nil)
	}
	if err != nil {
		return out, err
	}
	var payload struct {
		Selection   retirementSelectionPayload `json:"selection"`
		Attribution audit.Attribution          `json:"attribution"`
	}
	if json.Unmarshal([]byte(canonical), &payload) != nil {
		return LocalRetirementDraft{}, newStoreError(generated.ErrorCodeIntegrityFailure, "local-retirement-draft", false, nil)
	}
	out.Selection = LocalRetirementStageRequest{RepositoryID: payload.Selection.RepositoryID, RepositoryClass: payload.Selection.RepositoryClass, CatalogDigest: payload.Selection.CatalogDigest, ExpectedInventoryDigest: payload.Selection.ExpectedInventoryDigest, SelectionDigest: out.SelectionDigest, LockCatalogDigest: payload.Selection.LockCatalogDigest, SourceCoverageDigest: payload.Selection.SourceCoverageDigest, LockCatalogSequence: payload.Selection.LockCatalogSequence, Targets: payload.Selection.Targets, Survivors: payload.Selection.Survivors, SourceRevision: payload.Selection.SourceRevision, StateRevision: payload.Selection.StateRevision, RecoveryEpoch: payload.Selection.RecoveryEpoch, ExpectedReclaimBytes: payload.Selection.ExpectedReclaimBytes, MaxWorkObjects: payload.Selection.MaxWorkObjects, MaxMutationBytes: payload.Selection.MaxMutationBytes, MaxRepackBytes: payload.Selection.MaxRepackBytes, CapacityTotalBytes: payload.Selection.CapacityTotalBytes, CapacityAvailableBytes: payload.Selection.CapacityAvailableBytes, CapacityRetainedBytes: payload.Selection.CapacityRetainedBytes, CapacityQuarantinedBytes: payload.Selection.CapacityQuarantinedBytes, CapacityExpectedGrowthBytes: payload.Selection.CapacityExpectedGrowthBytes}
	out.Attribution = payload.Attribution
	_, digest, e := canonicalRetirementSelection(out.Selection)
	if e != nil || digest != out.SelectionDigest {
		return LocalRetirementDraft{}, newStoreError(generated.ErrorCodeIntegrityFailure, "local-retirement-draft", false, e)
	}
	return out, nil
}
