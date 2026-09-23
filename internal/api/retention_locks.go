package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type RetentionLockDraftService interface {
	CreateDraft(context.Context, generated.BackupRetentionLockDraftRequest, identity.Principal) (generated.BackupRetentionLockDraftSubmission, error)
}

type retentionLockDraftService struct {
	repository   *store.LocalRetirementRepository
	revisions    *store.PlanRepository
	declarations *change.Service
	authorizer   EffectiveAuthorizer
}

func NewRetentionLockDraftService(repository *store.LocalRetirementRepository, revisions *store.PlanRepository, declarations *change.Service, authorizer EffectiveAuthorizer) (RetentionLockDraftService, error) {
	if repository == nil || revisions == nil || declarations == nil || authorizer == nil {
		return nil, apiFailure(generated.ErrorCodeInputInvalid, "retention-lock-draft-config")
	}
	return &retentionLockDraftService{repository: repository, revisions: revisions, declarations: declarations, authorizer: authorizer}, nil
}

func retentionLockDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func retentionLockCatalog(input generated.LocalRetentionLockCatalog) store.LocalRetentionLockCatalog {
	locks := make([]store.LocalRetentionLock, len(input.Locks))
	for index, lock := range input.Locks {
		locks[index] = store.LocalRetentionLock{PointID: lock.PointID, ReasonDigest: lock.ReasonDigest}
	}
	return store.LocalRetentionLockCatalog{Schema: input.Schema, SchemaVersion: input.SchemaVersion, RepositoryID: input.RepositoryID, RepositoryClass: input.RepositoryClass, SourceCoverageDigest: input.SourceCoverageDigest, RecoveryEpoch: input.RecoveryEpoch, Revision: input.Revision, Complete: input.Complete, Locks: locks}
}

func (service *retentionLockDraftService) CreateDraft(ctx context.Context, input generated.BackupRetentionLockDraftRequest, principal identity.Principal) (generated.BackupRetentionLockDraftSubmission, error) {
	var zero generated.BackupRetentionLockDraftSubmission
	if !identity.ValidPrincipal(principal) || principal.Method != identity.LocalOSPeerMethod || identity.EffectivePrincipalKind(principal) != identity.PrincipalHuman {
		return zero, apiFailure(generated.ErrorCodeAuthorizationDenied, "retention-lock-operator-only")
	}
	raw, err := json.Marshal(input)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDBackupRetentionLockDraftRequest, raw, generated.ContractExact) != nil || input.Catalog.RecoveryEpoch != input.RecoveryEpoch {
		return zero, apiFailure(generated.ErrorCodeInputInvalid, "retention-lock-draft-request")
	}
	catalog := retentionLockCatalog(input.Catalog)
	_, catalogDigest, err := store.CanonicalLocalRetentionLockCatalog(catalog)
	if err != nil || input.TargetDigest != catalogDigest {
		return zero, apiFailure(generated.ErrorCodeInputInvalid, "retention-lock-catalog")
	}
	target := authorization.Target{Capability: "backup.retention-locks.author", ResourceKind: "backup-repository", ResourceID: catalog.RepositoryID}
	decision, err := service.authorizer.Authorize(ctx, principal, authorization.Request{Action: authorization.ActionAuthor, Target: target})
	if err != nil || !decision.Allowed || decision.PrincipalID != principal.ID || decision.Target != target {
		return zero, apiFailure(generated.ErrorCodeAuthorizationDenied, "retention-lock-author")
	}
	keyDigest := retentionLockDigest(input.IdempotencyKey)
	changeID := "retention-lock-change-" + keyDigest[7:39]
	operationID := "retention-lock-operation-" + keyDigest[7:39]
	if existing, lookupErr := service.repository.GetLocalRetentionLockCatalogDraftByKey(ctx, keyDigest, input.RecoveryEpoch); lookupErr == nil {
		if existing.CatalogDigest != catalogDigest || existing.DeclarationID != changeID {
			return zero, apiFailure(generated.ErrorCodeStateConflict, "retention-lock-idempotency")
		}
		return generated.BackupRetentionLockDraftSubmission{Schema: generated.SchemaIDBackupRetentionLockDraftSubmission, SchemaVersion: "1.1.0", DraftID: existing.DraftID, ChangeID: changeID, OperationID: operationID, CatalogDigest: catalogDigest, Status: "draft", StateRevision: existing.StateRevision, RecoveryEpoch: existing.RecoveryEpoch}, nil
	} else if store.Code(lookupErr) != generated.ErrorCodeResourceNotFound {
		return zero, lookupErr
	}
	current, err := service.revisions.CurrentRevision(ctx)
	if err != nil {
		return zero, err
	}
	if current != (store.RevisionToken{StateRevision: input.ExpectedStateRevision, RecoveryEpoch: input.RecoveryEpoch}) || catalog.Revision != 2 {
		return zero, apiFailure(generated.ErrorCodePlanStale, "retention-lock-revision")
	}
	requestDigest := retentionLockDigest("retention-lock-request-v1\x00" + principal.ID + "\x00" + string(raw))
	declaration := generated.DeclarationRevisionRequest{Schema: generated.SchemaIDDeclarationRevisionRequest, SchemaVersion: "1.0.0", DeclarationID: changeID, DeclarationType: "backup.retention-locks", ExpectedRevision: 1, ExpectedStateRevision: input.ExpectedStateRevision, RecoveryEpoch: input.RecoveryEpoch, ReasonDigest: requestDigest, Operations: []generated.DeclarationOperation{{Sequence: 1, OperationID: operationID, OperationType: "backup.retention-locks.activate", AdapterID: "core.retention-locks", TargetID: catalog.RepositoryID, InputDigest: catalogDigest, ArtifactDigest: catalog.SourceCoverageDigest, Idempotent: false}}, Extensions: []generated.ContractExtension{{Name: "x-backup-retention-lock-catalog", ValueDigest: catalogDigest}}}
	draft, err := service.declarations.Revise(ctx, change.AuthorScope{PrincipalID: principal.ID, PrincipalMethod: principal.Method, AgentSessionID: "session-" + requestDigest[7:39]}, declaration)
	if err != nil {
		return zero, err
	}
	stored, err := service.repository.PutLocalRetentionLockCatalogDraft(ctx, store.LocalRetentionLockCatalogDraftRequest{Catalog: catalog, DeclarationID: changeID, DeclarationRevision: draft.Document.Revision, Expected: store.RevisionToken{StateRevision: draft.Document.StateRevision, RecoveryEpoch: input.RecoveryEpoch}, IdempotencyKey: input.IdempotencyKey, RequestDigest: requestDigest, Attribution: audit.Attribution{AuthenticatedPrincipalID: principal.ID, AuthenticatedPrincipalMethod: principal.Method}})
	if err != nil {
		return zero, err
	}
	return generated.BackupRetentionLockDraftSubmission{Schema: generated.SchemaIDBackupRetentionLockDraftSubmission, SchemaVersion: "1.1.0", DraftID: stored.DraftID, ChangeID: changeID, OperationID: operationID, CatalogDigest: catalogDigest, Status: "draft", StateRevision: stored.StateRevision, RecoveryEpoch: stored.RecoveryEpoch}, nil
}

func (app *Application) backupRetentionLockDraft(config BackupOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, request *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const operation = "api.v1.backup-retention-lock-drafts.create"
		principal, ok := identity.PrincipalFromContext(request.Context())
		if !ok || principal.Method != identity.LocalOSPeerMethod || request.URL.RawQuery != "" {
			app.failure(w, operation, apiFailure(generated.ErrorCodeAuthorizationDenied, "retention-lock-operator-only"))
			return
		}
		var input generated.BackupRetentionLockDraftRequest
		if err := decodeOperationRequest(request, 65536, []string{"schema", "schemaVersion", "expectedStateRevision", "recoveryEpoch", "targetDigest", "idempotencyKey", "catalog"}, &input); err != nil {
			app.failure(w, operation, err)
			return
		}
		requestID, err := config.Results.RequestID()
		if err != nil {
			app.failure(w, operation, err)
			return
		}
		value, err := config.RetentionLocks.CreateDraft(request.Context(), input, principal)
		if err != nil {
			app.operationFailure(w, operation, requestID, err)
			return
		}
		app.operationSuccess(w, operation, requestID, true, value.StateRevision, value.RecoveryEpoch, value)
	}
}
