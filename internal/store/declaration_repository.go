package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostreplacement"
)

type DeclarationRevisionRequest struct {
	RestoreRequest *generated.RestoreRequest
	Document       generated.DeclarationRevision
	ReasonDigest   string
	Expected       RevisionToken
	KeyDigest      string
	RequestDigest  string
	Attribution    audit.Attribution
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
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDDeclarationRevision, canonical, generated.ContractExact) != nil || !validOffsiteDeclarationShape(request.Document) {
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
		if request.Document.AuthorizationGrantBatch != nil {
			if err := stageGrantBatchRows(ctx, transaction, *request.Document.AuthorizationGrantBatch, request.Attribution.AuthenticatedPrincipalID, request.Document.CreatedAt); err != nil {
				return err
			}
		}
		row := func(q string, a ...any) *sql.Row { return transaction.QueryRowContext(ctx, q, a...) }
		var owners []authorization.Target
		// Credential bindings are sealed immediately after this inert declaration;
		// their own writer rechecks the actual reference grant.
		var err error
		if request.Document.DeclarationType == "recovery.restore" {
			owners, err = restoreDraftAuthorizationTargets(ctx, row, request)
		} else if request.Document.DeclarationType != "credential.lifecycle" {
			owners, err = workflowDeclarationTargets(row, request.Document, authorization.ActionAuthor)
		}
		if err != nil {
			return err
		}
		for _, owner := range owners {
			actor, err := adoptionGrant(ctx, row, owner.ResourceID, owner.ResourceKind, string(authorization.WorkflowOwnerAction(authorization.ActionAuthor, owner)), owner.Capability, workflowAuthorRequiresAdministrator(owner) && owner.Capability != "host.read")
			if err != nil {
				return err
			}
			if actor != request.Attribution.AuthenticatedPrincipalID {
				return actionError(generated.ErrorCodeAuthorizationDenied)
			}
		}
		var latest int64
		if err := transaction.QueryRowContext(ctx, `SELECT COALESCE(MAX(declaration_revision),0) FROM declaration_revisions WHERE declaration_id=?`, request.Document.DeclarationID).Scan(&latest); err != nil {
			return err
		}
		if request.Document.Revision != latest+1 {
			return newStoreError(generated.ErrorCodeStateConflict, "declaration-revision", false, nil)
		}
		_, err = transaction.ExecContext(ctx, `INSERT INTO declaration_revisions(declaration_id,declaration_revision,declaration_type,state_revision,recovery_epoch,content_digest,reason_digest,status,canonical_bytes,created_at,created_by,agent_session_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, request.Document.DeclarationID, request.Document.Revision, request.Document.DeclarationType, request.Document.StateRevision, request.Document.RecoveryEpoch, request.Document.ContentDigest, request.ReasonDigest, request.Document.Status, canonical, request.Document.CreatedAt, request.Document.CreatedBy, request.Document.AgentSessionID)
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
	return ValidateGrantBatchDeclaration(document) && validAliasClaimDeclarationShape(document, reasonDigest) && validOffsiteDeclarationShape(document) && document.ContentDigest == declarationContentDigest(document, reasonDigest)
}

func validOffsiteDeclarationShape(document generated.DeclarationRevision) bool {
	if document.DeclarationType != "backup.offsite" {
		for _, operation := range document.Operations {
			if operation.OffsiteRunSpec != nil {
				return false
			}
		}
		return true
	}
	if len(document.Operations) != 1 {
		return false
	}
	operation, spec := document.Operations[0], document.Operations[0].OffsiteRunSpec
	return spec != nil && operation.OperationType == "backup.offsite.copy" && operation.AdapterID == "labs.r2-offsite" && !operation.Idempotent &&
		operation.TargetID == spec.GenerationID && spec.ParentReferenceID != spec.RepositoryKeyReferenceID && spec.ParentReferenceID != spec.ObserverReferenceID && spec.RepositoryKeyReferenceID != spec.ObserverReferenceID
}

func declarationContentDigest(document generated.DeclarationRevision, reasonDigest string) string {
	semantic := struct {
		HostAliasClaim          *generated.HostAliasClaimRequest          `json:"hostAliasClaim,omitempty"`
		AuthorizationGrantBatch *generated.AuthorizationGrantBatchRequest `json:"grantBatch,omitempty"`
		DeclarationID           string                                    `json:"declarationId"`
		DeclarationType         string                                    `json:"declarationType"`
		Operations              []generated.DeclarationOperation          `json:"operations"`
		ReasonDigest            string                                    `json:"reasonDigest"`
		Extensions              []generated.ContractExtension             `json:"extensions"`
	}{document.HostAliasClaim, document.AuthorizationGrantBatch, document.DeclarationID, document.DeclarationType, document.Operations, reasonDigest, document.Extensions}
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

func validAliasClaimDeclarationShape(d generated.DeclarationRevision, reason string) bool {
	present := d.HostAliasClaim != nil || d.DeclarationType == "host.alias-claim"
	for _, op := range d.Operations {
		present = present || op.OperationType == hostreplacement.AliasClaimOperation
	}
	for _, e := range d.Extensions {
		present = present || e.Name == hostreplacement.AliasClaimExtension
	}
	if !present {
		return true
	}
	if d.HostAliasClaim == nil || hostreplacement.ValidateAliasClaim(*d.HostAliasClaim) != nil || d.DeclarationType != "host.alias-claim" || len(d.Operations) != 1 || len(d.Extensions) != 1 || (d.Status == "draft" && d.HostAliasClaim.ExpectedStateRevision+1 != d.StateRevision || d.Status != "draft" && d.HostAliasClaim.ExpectedStateRevision >= d.StateRevision) || d.HostAliasClaim.RecoveryEpoch != d.RecoveryEpoch {
		return false
	}
	digest := hostaction.Digest(d.HostAliasClaim)
	op := d.Operations[0]
	return op.OperationType == hostreplacement.AliasClaimOperation && op.AdapterID == hostreplacement.AdapterID && op.TargetID == d.DeclarationID && op.Idempotent && op.InputDigest == digest && op.ArtifactDigest == digest && d.Extensions[0].Name == hostreplacement.AliasClaimExtension && d.Extensions[0].ValueDigest == digest && reason == digest
}
