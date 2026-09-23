package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

type LocalRetentionLockCatalogDraft struct {
	DraftID, CatalogDigest, DeclarationID, RepositoryID, RepositoryClass string
	DeclarationRevision, StateRevision, RecoveryEpoch                    int64
	Catalog                                                              LocalRetentionLockCatalog
	CreatedBy, CreatedAt                                                 string
}

type LocalRetentionLockCatalogDraftRequest struct {
	Catalog                       LocalRetentionLockCatalog
	DeclarationID                 string
	DeclarationRevision           int64
	Expected                      RevisionToken
	IdempotencyKey, RequestDigest string
	Attribution                   audit.Attribution
}

// PutLocalRetentionLockCatalogDraft stores the complete catalog bytes behind
// the exact declaration extension digest. The draft grants no lock authority;
// only its later human-plan core effect can append an activation generation.
func (repository *LocalRetirementRepository) PutLocalRetentionLockCatalogDraft(ctx context.Context, request LocalRetentionLockCatalogDraftRequest) (LocalRetentionLockCatalogDraft, error) {
	var zero LocalRetentionLockCatalogDraft
	canonical, catalogDigest, err := CanonicalLocalRetentionLockCatalog(request.Catalog)
	if repository == nil || repository.store == nil || err != nil || !validRetirementID(request.DeclarationID) || request.DeclarationRevision < 1 ||
		request.Catalog.Revision != request.DeclarationRevision+1 || request.Expected.StateRevision < 1 || request.Expected.RecoveryEpoch != request.Catalog.RecoveryEpoch ||
		!validRetirementID(request.IdempotencyKey) || !validBackupDigest(request.RequestDigest) || request.Attribution.AuthenticatedPrincipalID == "" || request.Attribution.AuthenticatedPrincipalMethod == "" {
		return zero, newStoreError(generated.ErrorCodeInputInvalid, "local-retention-lock-draft", false, err)
	}
	keySum := sha256.Sum256([]byte(request.IdempotencyKey))
	keyDigest := "sha256:" + hex.EncodeToString(keySum[:])
	draftID := "lock-draft-" + strings.TrimPrefix(catalogDigest, "sha256:")[:32]
	if existing, lookupErr := repository.GetLocalRetentionLockCatalogDraftByKey(ctx, keyDigest, request.Expected.RecoveryEpoch); lookupErr == nil {
		if existing.CatalogDigest != catalogDigest || existing.DeclarationID != request.DeclarationID || existing.DeclarationRevision != request.DeclarationRevision {
			return zero, newStoreError(generated.ErrorCodeStateConflict, "local-retention-lock-draft-idempotency", false, nil)
		}
		return existing, nil
	} else if Code(lookupErr) != generated.ErrorCodeResourceNotFound {
		return zero, lookupErr
	}
	createdAt := repository.store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339)
	after := audit.Fingerprint(catalogDigest)
	event := audit.EventDraft{Type: "backup.retention-lock-catalog-draft-created", CorrelationID: draftID, Attribution: request.Attribution, Target: audit.Target{Kind: "backup-retention-lock-catalog-draft", ID: draftID}, After: &after}
	key := audit.IntentKey{Scope: "local-retention-lock-catalog-draft", KeyDigest: audit.Fingerprint(keyDigest), RequestDigest: audit.Fingerprint(request.RequestDigest)}
	if audit.ValidateIntentKey(key) != nil || audit.ValidateEventDraft(event) != nil {
		return zero, newStoreError(generated.ErrorCodeInputInvalid, "local-retention-lock-draft-audit", false, nil)
	}
	intent, err := repository.store.writeIntent(ctx, intentRequest{Expected: &request.Expected, Idempotency: key, Event: event}, func(ctx context.Context, tx *sql.Tx) error {
		var declarationType, status string
		var stateRevision, epoch int64
		if err := tx.QueryRowContext(ctx, `SELECT declaration_type,status,state_revision,recovery_epoch FROM declaration_revisions WHERE declaration_id=? AND declaration_revision=?`, request.DeclarationID, request.DeclarationRevision).Scan(&declarationType, &status, &stateRevision, &epoch); err != nil {
			return err
		}
		if declarationType != "backup.retention-locks" || status != "draft" || stateRevision != request.Expected.StateRevision || epoch != request.Expected.RecoveryEpoch {
			return newStoreError(generated.ErrorCodePrerequisiteBlocked, "local-retention-lock-declaration", false, nil)
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO backup_retention_lock_catalog_drafts(draft_id,catalog_digest,repository_id,repository_class,declaration_id,declaration_revision,canonical_json,idempotency_key_digest,state_revision,recovery_epoch,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
			draftID, catalogDigest, request.Catalog.RepositoryID, request.Catalog.RepositoryClass, request.DeclarationID, request.DeclarationRevision, string(canonical), keyDigest, request.Expected.StateRevision+1, request.Expected.RecoveryEpoch, request.Attribution.AuthenticatedPrincipalID, createdAt)
		return err
	})
	if err != nil {
		return zero, err
	}
	return LocalRetentionLockCatalogDraft{DraftID: draftID, CatalogDigest: catalogDigest, DeclarationID: request.DeclarationID, RepositoryID: request.Catalog.RepositoryID, RepositoryClass: request.Catalog.RepositoryClass, DeclarationRevision: request.DeclarationRevision, StateRevision: intent.Commit.StateRevision, RecoveryEpoch: intent.Commit.RecoveryEpoch, Catalog: request.Catalog, CreatedBy: request.Attribution.AuthenticatedPrincipalID, CreatedAt: createdAt}, nil
}

func (repository *LocalRetirementRepository) GetLocalRetentionLockCatalogDraft(ctx context.Context, digest string, epoch int64) (LocalRetentionLockCatalogDraft, error) {
	return repository.scanLocalRetentionLockCatalogDraft(ctx, `WHERE catalog_digest=? AND recovery_epoch=?`, digest, epoch)
}

func (repository *LocalRetirementRepository) GetLocalRetentionLockCatalogDraftByKey(ctx context.Context, keyDigest string, epoch int64) (LocalRetentionLockCatalogDraft, error) {
	return repository.scanLocalRetentionLockCatalogDraft(ctx, `WHERE idempotency_key_digest=? AND recovery_epoch=?`, keyDigest, epoch)
}

func (repository *LocalRetirementRepository) scanLocalRetentionLockCatalogDraft(ctx context.Context, clause string, args ...any) (LocalRetentionLockCatalogDraft, error) {
	var value LocalRetentionLockCatalogDraft
	var canonical string
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT draft_id,catalog_digest,repository_id,repository_class,declaration_id,declaration_revision,canonical_json,state_revision,recovery_epoch,created_by,created_at FROM backup_retention_lock_catalog_drafts `+clause, args...).Scan(&value.DraftID, &value.CatalogDigest, &value.RepositoryID, &value.RepositoryClass, &value.DeclarationID, &value.DeclarationRevision, &canonical, &value.StateRevision, &value.RecoveryEpoch, &value.CreatedBy, &value.CreatedAt)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return value, newStoreError(generated.ErrorCodeResourceNotFound, "local-retention-lock-draft", false, nil)
	}
	if err != nil || json.Unmarshal([]byte(canonical), &value.Catalog) != nil {
		return LocalRetentionLockCatalogDraft{}, newStoreError(generated.ErrorCodeIntegrityFailure, "local-retention-lock-draft", false, err)
	}
	remarshal, digest, canonicalErr := CanonicalLocalRetentionLockCatalog(value.Catalog)
	if canonicalErr != nil || string(remarshal) != canonical || digest != value.CatalogDigest {
		return LocalRetentionLockCatalogDraft{}, newStoreError(generated.ErrorCodeIntegrityFailure, "local-retention-lock-draft", false, canonicalErr)
	}
	return value, nil
}
