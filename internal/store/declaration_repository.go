package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

type DeclarationRevisionRequest struct {
	Document      generated.DeclarationRevision
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
	if repository == nil || repository.store == nil || request.Document.StateRevision != request.Expected.StateRevision+1 || request.Document.RecoveryEpoch != request.Expected.RecoveryEpoch {
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
	result := DeclarationRevisionResult{Document: request.Document}
	intent, err := repository.store.writeIntent(ctx, intentRequest{Expected: &request.Expected, Idempotency: key, Event: event}, func(ctx context.Context, transaction *sql.Tx) error {
		var latest int64
		if err := transaction.QueryRowContext(ctx, `SELECT COALESCE(MAX(declaration_revision),0) FROM declaration_revisions WHERE declaration_id=?`, request.Document.DeclarationID).Scan(&latest); err != nil {
			return err
		}
		if request.Document.Revision != latest+1 {
			return newStoreError(generated.ErrorCodeStateConflict, "declaration-revision", false, nil)
		}
		_, err := transaction.ExecContext(ctx, `INSERT INTO declaration_revisions(declaration_id,declaration_revision,declaration_type,state_revision,recovery_epoch,content_digest,status,canonical_bytes,created_at,created_by,agent_session_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, request.Document.DeclarationID, request.Document.Revision, request.Document.DeclarationType, request.Document.StateRevision, request.Document.RecoveryEpoch, request.Document.ContentDigest, request.Document.Status, canonical, request.Document.CreatedAt, request.Document.CreatedBy, request.Document.AgentSessionID)
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

func (repository *DeclarationRepository) GetRevision(ctx context.Context, declarationID string, revision int64) (generated.DeclarationRevision, error) {
	var raw []byte
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT canonical_bytes FROM declaration_revisions WHERE declaration_id=? AND declaration_revision=?`, declarationID, revision).Scan(&raw)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return generated.DeclarationRevision{}, newStoreError(generated.ErrorCodeResourceNotFound, "declaration-revision", false, nil)
	}
	if err != nil {
		return generated.DeclarationRevision{}, err
	}
	var document generated.DeclarationRevision
	if json.Unmarshal(raw, &document) != nil || generated.ValidateContractJSON(generated.SchemaIDDeclarationRevision, raw, generated.ContractCompatibleRead) != nil {
		return generated.DeclarationRevision{}, newStoreError(generated.ErrorCodeIntegrityFailure, "declaration-revision", false, nil)
	}
	return document, nil
}
