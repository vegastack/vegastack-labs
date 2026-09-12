package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

type DeclarationRevisionRequest struct {
	Document      generated.DeclarationRevision
	ReasonDigest  string
	Expected      RevisionToken
	KeyDigest     string
	RequestDigest string
	Attribution   audit.Attribution
}

type DeclarationRevisionResult struct {
	Document generated.DeclarationRevision
	Commit   Commit
	Created  bool
}

type DeclarationRepository struct{ store *Store }

func NewDeclarationRepository(store *Store) *DeclarationRepository {
	return &DeclarationRepository{store: store}
}

func (repository *DeclarationRepository) CreateRevision(ctx context.Context, request DeclarationRevisionRequest) (DeclarationRevisionResult, error) {
	if repository == nil || repository.store == nil || request.Document.Status != "draft" || request.Document.StateRevision != request.Expected.StateRevision+1 || request.Document.RecoveryEpoch != request.Expected.RecoveryEpoch || !validDeclarationContent(request.Document, request.ReasonDigest) {
		return DeclarationRevisionResult{}, newStoreError(generated.ErrorCodeInputInvalid, "declaration-revision", false, nil)
	}
	canonical, err := json.Marshal(request.Document)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDDeclarationRevision, canonical, generated.ContractExact) != nil {
		return DeclarationRevisionResult{}, newStoreError(generated.ErrorCodeInputInvalid, "declaration-revision", false, err)
	}
	key := audit.IntentKey{Scope: "declaration-revision", KeyDigest: audit.Fingerprint(request.KeyDigest), RequestDigest: audit.Fingerprint(request.RequestDigest)}
	after := audit.Fingerprint(request.Document.ContentDigest)
	event := audit.EventDraft{Type: "declaration.revision-created", CorrelationID: request.KeyDigest, Attribution: request.Attribution, Target: audit.Target{Kind: "declaration", ID: request.Document.DeclarationID}, After: &after}
	if audit.ValidateIntentKey(key) != nil || audit.ValidateEventDraft(event) != nil {
		return DeclarationRevisionResult{}, newStoreError(generated.ErrorCodeInputInvalid, "declaration-revision", false, nil)
	}
	if existing, found, err := repository.existing(ctx, request); err != nil || found {
		return existing, err
	}
	result := DeclarationRevisionResult{Document: request.Document}
	intent, err := repository.store.writeIntent(ctx, intentRequest{Expected: &request.Expected, Idempotency: key, Event: event}, func(ctx context.Context, transaction *sql.Tx) error {
		var latest int64
		if err := transaction.QueryRowContext(ctx, `SELECT COALESCE(MAX(declaration_revision),0) FROM declaration_revisions WHERE declaration_id=?`, request.Document.DeclarationID).Scan(&latest); err != nil {
			return err
		}
		if request.Document.Revision != latest+1 {
			return newStoreError(generated.ErrorCodeStateConflict, "declaration-revision", false, nil)
		}
		_, err := transaction.ExecContext(ctx, `INSERT INTO declaration_revisions(declaration_id,declaration_revision,declaration_type,state_revision,recovery_epoch,content_digest,reason_digest,status,canonical_bytes,created_at,created_by,agent_session_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, request.Document.DeclarationID, request.Document.Revision, request.Document.DeclarationType, request.Document.StateRevision, request.Document.RecoveryEpoch, request.Document.ContentDigest, request.ReasonDigest, request.Document.Status, canonical, request.Document.CreatedAt, request.Document.CreatedBy, request.Document.AgentSessionID)
		return err
	})
	if err != nil {
		return DeclarationRevisionResult{}, err
	}
	if !intent.Created {
		document, getErr := repository.GetRevision(ctx, request.Document.DeclarationID, request.Document.Revision)
		if getErr != nil {
			return DeclarationRevisionResult{}, getErr
		}
		result.Document = document
	}
	result.Commit, result.Created = intent.Commit, intent.Created
	return result, nil
}

func (repository *DeclarationRepository) existing(ctx context.Context, request DeclarationRevisionRequest) (DeclarationRevisionResult, bool, error) {
	var storedDigest string
	var revision, epoch int64
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT request_digest,state_revision,recovery_epoch FROM intent_keys WHERE scope='declaration-revision' AND key_digest=?`, request.KeyDigest).Scan(&storedDigest, &revision, &epoch)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return DeclarationRevisionResult{}, false, nil
	}
	if err != nil {
		return DeclarationRevisionResult{}, false, err
	}
	if storedDigest != request.RequestDigest {
		return DeclarationRevisionResult{}, true, newStoreError(generated.ErrorCodeStateConflict, "declaration-intent-key", false, nil)
	}
	document, err := repository.GetRevision(ctx, request.Document.DeclarationID, request.Document.Revision)
	if err != nil {
		return DeclarationRevisionResult{}, true, err
	}
	return DeclarationRevisionResult{Document: document, Commit: Commit{Changed: false, StateRevision: revision, RecoveryEpoch: epoch}, Created: false}, true, nil
}

func (repository *DeclarationRepository) GetRevision(ctx context.Context, declarationID string, revision int64) (generated.DeclarationRevision, error) {
	var raw []byte
	var reasonDigest string
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT canonical_bytes,reason_digest FROM declaration_revisions WHERE declaration_id=? AND declaration_revision=?`, declarationID, revision).Scan(&raw, &reasonDigest)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return generated.DeclarationRevision{}, newStoreError(generated.ErrorCodeResourceNotFound, "declaration-revision", false, nil)
	}
	if err != nil {
		return generated.DeclarationRevision{}, err
	}
	var document generated.DeclarationRevision
	if !decodeStoredDeclaration(raw, reasonDigest, &document) {
		return generated.DeclarationRevision{}, newStoreError(generated.ErrorCodeIntegrityFailure, "declaration-revision", false, nil)
	}
	return document, nil
}

func decodeStoredDeclaration(raw []byte, reasonDigest string, document *generated.DeclarationRevision) bool {
	if json.Unmarshal(raw, document) != nil || generated.ValidateContractJSON(generated.SchemaIDDeclarationRevision, raw, generated.ContractExact) != nil || !validDeclarationContent(*document, reasonDigest) {
		return false
	}
	reencoded, err := json.Marshal(document)
	return err == nil && string(reencoded) == string(raw)
}

func validDeclarationContent(document generated.DeclarationRevision, reasonDigest string) bool {
	return document.ContentDigest == declarationContentDigest(document, reasonDigest)
}

func declarationContentDigest(document generated.DeclarationRevision, reasonDigest string) string {
	semantic := struct {
		DeclarationID   string                           `json:"declarationId"`
		DeclarationType string                           `json:"declarationType"`
		Operations      []generated.DeclarationOperation `json:"operations"`
		ReasonDigest    string                           `json:"reasonDigest"`
		Extensions      []generated.ContractExtension    `json:"extensions"`
	}{document.DeclarationID, document.DeclarationType, document.Operations, reasonDigest, document.Extensions}
	encoded, err := json.Marshal(semantic)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (repository *DeclarationRepository) GetReasonDigest(ctx context.Context, declarationID string, revision int64) (string, error) {
	var result string
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT reason_digest FROM declaration_revisions WHERE declaration_id=? AND declaration_revision=?`, declarationID, revision).Scan(&result)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return "", newStoreError(generated.ErrorCodeResourceNotFound, "declaration-revision", false, nil)
	}
	return result, err
}
