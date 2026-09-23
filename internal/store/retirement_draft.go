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
	Points                       []LocalRetirementDraftInput
	LastGoodIDs                  []string
	Objects                      []ExpectedObjectRow
	Locks                        AppliedLocalRetentionLocks
	StateRevision, RecoveryEpoch int64
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
		rows, err := tx.query(ctx, `SELECT p.point_id,p.snapshot_id,p.repository_id,p.manifest_digest,p.inventory_digest,p.object_bytes,p.source_revision,p.recovery_epoch,p.created_at,p.manifest_json,v.proof_digest
			FROM recovery_points p JOIN backup_local_verifications v ON v.verification_id=(SELECT verification_id FROM backup_local_verifications WHERE point_id=p.point_id AND status='local-verified' AND proof_class='live' ORDER BY created_at DESC,verification_id DESC LIMIT 1)
			WHERE p.repository_class=? AND p.recovery_epoch=? ORDER BY p.point_id`, class, epoch)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var point LocalRetirementDraftInput
			var created, manifestJSON string
			if err := rows.Scan(&point.PointID, &point.SnapshotID, &point.RepositoryID, &point.ManifestDigest, &point.InventoryDigest, &point.Bytes, &point.SourceRevision, &point.RecoveryEpoch, &created, &manifestJSON, &point.ProofDigest); err != nil {
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
			result.Points = append(result.Points, point)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		var total int
		if err := tx.queryRow(ctx, `SELECT COUNT(*) FROM recovery_points WHERE repository_class=? AND recovery_epoch=?`, class, epoch).Scan(&total); err != nil {
			return err
		}
		if total == 0 || total != len(result.Points) {
			return newStoreError(generated.ErrorCodePrerequisiteBlocked, "local-retirement-unverified-point", false, nil)
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
		objects, err := tx.query(ctx, `SELECT o.object_type,o.object_name,o.object_bytes,o.object_digest FROM backup_expected_objects o JOIN recovery_points p ON p.point_id=o.point_id WHERE p.repository_class=? AND p.recovery_epoch=? ORDER BY o.object_type,o.object_name,p.point_id`, class, epoch)
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
		sort.Slice(result.Objects, func(i, j int) bool {
			if result.Objects[i].Type == result.Objects[j].Type {
				return result.Objects[i].Name < result.Objects[j].Name
			}
			return result.Objects[i].Type < result.Objects[j].Type
		})
		if len(result.Objects) == 0 {
			return newStoreError(generated.ErrorCodePrerequisiteBlocked, "local-retirement-inventory", false, nil)
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
	out.Selection = LocalRetirementStageRequest{RepositoryID: payload.Selection.RepositoryID, RepositoryClass: payload.Selection.RepositoryClass, CatalogDigest: payload.Selection.CatalogDigest, ExpectedInventoryDigest: payload.Selection.ExpectedInventoryDigest, SelectionDigest: out.SelectionDigest, LockCatalogDigest: payload.Selection.LockCatalogDigest, SourceCoverageDigest: payload.Selection.SourceCoverageDigest, LockCatalogSequence: payload.Selection.LockCatalogSequence, Targets: payload.Selection.Targets, Survivors: payload.Selection.Survivors, SourceRevision: payload.Selection.SourceRevision, StateRevision: payload.Selection.StateRevision, RecoveryEpoch: payload.Selection.RecoveryEpoch, ExpectedReclaimBytes: payload.Selection.ExpectedReclaimBytes, MaxWorkObjects: payload.Selection.MaxWorkObjects, MaxMutationBytes: payload.Selection.MaxMutationBytes, MaxRepackBytes: payload.Selection.MaxRepackBytes}
	out.Attribution = payload.Attribution
	_, digest, e := canonicalRetirementSelection(out.Selection)
	if e != nil || digest != out.SelectionDigest {
		return LocalRetirementDraft{}, newStoreError(generated.ErrorCodeIntegrityFailure, "local-retirement-draft", false, e)
	}
	return out, nil
}
