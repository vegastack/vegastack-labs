package api

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/backup"
	"github.com/vegastack/vegastack-labs/internal/backupidentity"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type RetirementDraftService interface {
	CreateDraft(context.Context, generated.BackupRetirementDraftRequest, identity.Principal) (generated.BackupRetirementDraftSubmission, error)
}

type retirementDraftService struct {
	retirements  *store.LocalRetirementRepository
	credentials  *store.CredentialRepository
	revisions    *store.PlanRepository
	declarations *change.Service
	authorizer   EffectiveAuthorizer
}

func NewRetirementDraftService(retirements *store.LocalRetirementRepository, credentials *store.CredentialRepository, revisions *store.PlanRepository, declarations *change.Service, authorizer EffectiveAuthorizer) (RetirementDraftService, error) {
	if retirements == nil || credentials == nil || revisions == nil || declarations == nil || authorizer == nil {
		return nil, apiFailure(generated.ErrorCodeInputInvalid, "retirement-draft-config")
	}
	return &retirementDraftService{retirements: retirements, credentials: credentials, revisions: revisions, declarations: declarations, authorizer: authorizer}, nil
}

func retirementRepository(class string) (string, bool) {
	switch class {
	case "standard":
		return backupidentity.StandardRepository, true
	case "critical":
		return backupidentity.CriticalRepository, true
	default:
		return "", false
	}
}

func retirementSubmission(draft store.LocalRetirementDraft, binding credentialref.StepBinding, state int64) generated.BackupRetirementDraftSubmission {
	targets := make([]string, len(draft.Selection.Targets))
	for i, item := range draft.Selection.Targets {
		targets[i] = item.PointID
	}
	survivors := make([]string, len(draft.Selection.Survivors))
	for i, item := range draft.Selection.Survivors {
		survivors[i] = item.PointID
	}
	return generated.BackupRetirementDraftSubmission{Schema: generated.SchemaIDBackupRetirementDraftSubmission, SchemaVersion: "1.1.0", DraftID: draft.DraftID, ChangeID: draft.DeclarationID, OperationID: binding.OperationID, SelectionDigest: draft.SelectionDigest, CredentialManifestDigest: credentialref.OperationManifestDigest([]credentialref.StepBinding{binding}, binding.OperationID), TargetPointIDs: targets, SurvivorPointIDs: survivors, Status: "draft", StateRevision: state, RecoveryEpoch: draft.RecoveryEpoch}
}

func (service *retirementDraftService) CreateDraft(ctx context.Context, input generated.BackupRetirementDraftRequest, principal identity.Principal) (generated.BackupRetirementDraftSubmission, error) {
	var zero generated.BackupRetirementDraftSubmission
	raw, err := json.Marshal(input)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDBackupRetirementDraftRequest, raw, generated.ContractExact) != nil || !identity.ValidPrincipal(principal) || principal.Method != identity.LocalOSPeerMethod || identity.EffectivePrincipalKind(principal) != identity.PrincipalHuman {
		return zero, apiFailure(generated.ErrorCodeAuthorizationDenied, "retirement-draft-operator-only")
	}
	repositoryID, ok := retirementRepository(input.RepositoryClass)
	if !ok {
		return zero, apiFailure(generated.ErrorCodeInputInvalid, "retirement-repository")
	}
	targetDigest, err := store.LocalRepositoryPlanTargetDigest(repositoryID)
	if err != nil || targetDigest != input.TargetDigest {
		return zero, apiFailure(generated.ErrorCodeInputInvalid, "retirement-target")
	}
	target := authorization.Target{Capability: "backup.retirement.author", ResourceKind: "backup-repository", ResourceID: repositoryID}
	decision, err := service.authorizer.Authorize(ctx, principal, authorization.Request{Action: authorization.ActionAuthor, Target: target})
	if err != nil || !decision.Allowed || decision.PrincipalID != principal.ID || decision.Target != target {
		return zero, apiFailure(generated.ErrorCodeAuthorizationDenied, "retirement-author")
	}
	keyDigest := retentionLockDigest(input.IdempotencyKey)
	changeID := "retirement-change-" + keyDigest[7:39]
	operationID := "retirement-operation-" + keyDigest[7:39]
	if existing, lookup := service.retirements.GetLocalRetirementDraftByKey(ctx, keyDigest, input.RecoveryEpoch); lookup == nil {
		binding := credentialref.StepBinding{OperationID: operationID, AdapterID: "local.retention", TargetID: repositoryID, ReferenceID: input.ReferenceID, ConsumerID: "local.retention", PurposeID: "backup-retention", MaterialVersion: input.MaterialVersion, ResolverID: input.ResolverID, StateRevision: existing.Selection.StateRevision, RecoveryEpoch: input.RecoveryEpoch}
		if existing.DeclarationID != changeID || existing.Selection.RepositoryID != repositoryID {
			return zero, apiFailure(generated.ErrorCodeStateConflict, "retirement-idempotency")
		}
		current, revisionErr := service.revisions.CurrentRevision(ctx)
		if revisionErr != nil {
			return zero, revisionErr
		}
		found, bindingErr := service.credentials.HasExactStepBinding(ctx, existing.DeclarationID, existing.DeclarationRevision, binding)
		if bindingErr != nil {
			return zero, bindingErr
		}
		if !found {
			if current != (store.RevisionToken{StateRevision: existing.StateRevision, RecoveryEpoch: input.RecoveryEpoch}) {
				return zero, apiFailure(generated.ErrorCodePrerequisiteBlocked, "retirement-binding-missing")
			}
			requestDigest := retentionLockDigest("retirement-draft-v1\x00" + principal.ID + "\x00" + string(raw) + "\x00" + existing.SelectionDigest)
			manifest, stageErr := service.credentials.StageStepBindings(ctx, store.CredentialBindingStageRequest{DeclarationID: existing.DeclarationID, DeclarationRevision: existing.DeclarationRevision, Bindings: []credentialref.StepBinding{binding}, Expected: current, Attribution: existing.Attribution, KeyDigest: retentionLockDigest("retirement-binding-key\x00" + input.IdempotencyKey), RequestDigest: retentionLockDigest("retirement-binding-request\x00" + requestDigest)})
			if stageErr != nil {
				return zero, stageErr
			}
			if manifest != credentialref.OperationManifestDigest([]credentialref.StepBinding{binding}, binding.OperationID) {
				return zero, apiFailure(generated.ErrorCodeIntegrityFailure, "retirement-credential-manifest")
			}
			current.StateRevision++
		}
		return retirementSubmission(existing, binding, current.StateRevision), nil
	} else if store.Code(lookup) != generated.ErrorCodeResourceNotFound {
		return zero, lookup
	}
	current, err := service.revisions.CurrentRevision(ctx)
	if err != nil {
		return zero, err
	}
	if current != (store.RevisionToken{StateRevision: input.ExpectedStateRevision, RecoveryEpoch: input.RecoveryEpoch}) {
		return zero, apiFailure(generated.ErrorCodePlanStale, "retirement-revision")
	}
	sources, err := service.retirements.LoadLocalRetirementDraftSources(ctx, input.RepositoryClass, input.RecoveryEpoch)
	if err != nil {
		return zero, err
	}
	if sources.StateRevision != input.ExpectedStateRevision {
		return zero, apiFailure(generated.ErrorCodePlanStale, "retirement-sources")
	}
	candidates := make([]backup.RetirementCandidate, len(sources.Points))
	for i, p := range sources.Points {
		candidates[i] = backup.RetirementCandidate{PointID: p.PointID, SnapshotID: p.SnapshotID, RepositoryID: p.RepositoryID, ManifestDigest: p.ManifestDigest, DependencyDigest: p.DependencyDigest, InventoryDigest: p.InventoryDigest, ProofDigest: p.ProofDigest, CreatedAt: p.CreatedAt, Bytes: p.Bytes, RecoveryEpoch: p.RecoveryEpoch}
	}
	window := 7 * 24 * time.Hour
	if input.RepositoryClass == "critical" {
		window = 14 * 24 * time.Hour
	}
	selection, err := backup.SelectLocalRetirement(candidates, sources.LastGoodIDs, sources.Locks, window, input.RecoveryEpoch)
	if err != nil || len(selection.Targets) == 0 {
		return zero, apiFailure(generated.ErrorCodePrerequisiteBlocked, "retirement-empty-selection")
	}
	objects := make([]backup.ExpectedObject, len(sources.Objects))
	var bytes int64
	for i, o := range sources.Objects {
		objects[i] = backup.ExpectedObject{Type: o.Type, Name: o.Name, Bytes: o.Bytes, Digest: o.Digest}
		if o.Bytes > 0 && bytes > math.MaxInt64-o.Bytes {
			return zero, apiFailure(generated.ErrorCodeInputInvalid, "retirement-inventory-bytes")
		}
		bytes += o.Bytes
	}
	expectedInventory := backup.ExpectedInventoryDigest(objects)
	if expectedInventory == "" || bytes < 1 {
		return zero, apiFailure(generated.ErrorCodePrerequisiteBlocked, "retirement-inventory")
	}
	stage := store.LocalRetirementStageRequest{RepositoryID: repositoryID, RepositoryClass: input.RepositoryClass, CatalogDigest: selection.ExpectedInventoryDigest, ExpectedInventoryDigest: expectedInventory, LockCatalogDigest: selection.LockCatalogDigest, SourceCoverageDigest: selection.SourceCoverageDigest, LockCatalogSequence: selection.LockCatalogSequence, SourceRevision: 2, StateRevision: input.ExpectedStateRevision + 4, RecoveryEpoch: input.RecoveryEpoch, MaxWorkObjects: int64(len(objects)) * 2, MaxMutationBytes: bytes, MaxRepackBytes: bytes, Attribution: audit.Attribution{AuthenticatedPrincipalID: principal.ID, AuthenticatedPrincipalMethod: principal.Method}}
	for _, p := range selection.Targets {
		stage.Targets = append(stage.Targets, store.LocalRetirementTarget{PointID: p.PointID, SnapshotID: p.SnapshotID, ManifestDigest: p.ManifestDigest, InventoryDigest: p.InventoryDigest, DependencyDigest: p.DependencyDigest})
		stage.ExpectedReclaimBytes += p.Bytes
	}
	for _, p := range selection.Survivors {
		stage.Survivors = append(stage.Survivors, store.LocalRetirementSurvivor{PointID: p.PointID, SnapshotID: p.SnapshotID, ManifestDigest: p.ManifestDigest, InventoryDigest: p.InventoryDigest, DependencyDigest: p.DependencyDigest, ProofDigest: p.ProofDigest})
	}
	_, selectionDigest, err := store.CanonicalLocalRetirementSelection(stage)
	if err != nil {
		return zero, err
	}
	stage.SelectionDigest = selectionDigest
	binding := credentialref.StepBinding{OperationID: operationID, AdapterID: "local.retention", TargetID: repositoryID, ReferenceID: input.ReferenceID, ConsumerID: "local.retention", PurposeID: "backup-retention", MaterialVersion: input.MaterialVersion, ResolverID: input.ResolverID, StateRevision: stage.StateRevision, RecoveryEpoch: input.RecoveryEpoch}
	credentialDigest := credentialref.OperationManifestDigest([]credentialref.StepBinding{binding}, operationID)
	if credentialDigest == "" {
		return zero, apiFailure(generated.ErrorCodeInputInvalid, "retirement-credential-binding")
	}
	requestDigest := retentionLockDigest("retirement-draft-v1\x00" + principal.ID + "\x00" + string(raw) + "\x00" + selectionDigest)
	declaration := generated.DeclarationRevisionRequest{Schema: generated.SchemaIDDeclarationRevisionRequest, SchemaVersion: "1.0.0", DeclarationID: changeID, DeclarationType: "backup.retirement", ExpectedRevision: 1, ExpectedStateRevision: input.ExpectedStateRevision, RecoveryEpoch: input.RecoveryEpoch, ReasonDigest: requestDigest, Operations: []generated.DeclarationOperation{{Sequence: 1, OperationID: operationID, OperationType: "backup.local.retire", AdapterID: "local.retention", TargetID: repositoryID, InputDigest: credentialDigest, ArtifactDigest: expectedInventory, Idempotent: false}}, Extensions: []generated.ContractExtension{{Name: "x-backup-local-retirement", ValueDigest: selectionDigest}, {Name: "x-credential-bindings", ValueDigest: credentialDigest}}}
	draft, err := service.declarations.Revise(ctx, change.AuthorScope{PrincipalID: principal.ID, PrincipalMethod: principal.Method, AgentSessionID: "session-" + requestDigest[7:39]}, declaration)
	if err != nil {
		return zero, err
	}
	stored, err := service.retirements.PutLocalRetirementDraft(ctx, store.LocalRetirementDraftStoreRequest{Selection: stage, DeclarationID: changeID, DeclarationRevision: draft.Document.Revision, Expected: store.RevisionToken{StateRevision: draft.Document.StateRevision, RecoveryEpoch: input.RecoveryEpoch}, IdempotencyKey: input.IdempotencyKey, RequestDigest: requestDigest, Attribution: stage.Attribution})
	if err != nil {
		return zero, err
	}
	manifest, err := service.credentials.StageStepBindings(ctx, store.CredentialBindingStageRequest{DeclarationID: changeID, DeclarationRevision: draft.Document.Revision, Bindings: []credentialref.StepBinding{binding}, Expected: store.RevisionToken{StateRevision: stored.StateRevision, RecoveryEpoch: input.RecoveryEpoch}, Attribution: stage.Attribution, KeyDigest: retentionLockDigest("retirement-binding-key\x00" + input.IdempotencyKey), RequestDigest: retentionLockDigest("retirement-binding-request\x00" + requestDigest)})
	if err != nil {
		return zero, err
	}
	if manifest != credentialDigest {
		return zero, apiFailure(generated.ErrorCodeIntegrityFailure, "retirement-credential-manifest")
	}
	return retirementSubmission(stored, binding, stored.StateRevision+1), nil
}

func (app *Application) backupRetirementDraft(config BackupOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, request *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const operation = "api.v1.backup-retirement-drafts.create"
		principal, ok := identity.PrincipalFromContext(request.Context())
		if !ok || principal.Method != identity.LocalOSPeerMethod || request.URL.RawQuery != "" {
			app.failure(w, operation, apiFailure(generated.ErrorCodeAuthorizationDenied, "retirement-operator-only"))
			return
		}
		var input generated.BackupRetirementDraftRequest
		if err := decodeOperationRequest(request, 65536, []string{"schema", "schemaVersion", "expectedStateRevision", "recoveryEpoch", "targetDigest", "idempotencyKey", "repositoryClass", "referenceId", "resolverId", "materialVersion"}, &input); err != nil {
			app.failure(w, operation, err)
			return
		}
		requestID, err := config.Results.RequestID()
		if err != nil {
			app.failure(w, operation, err)
			return
		}
		value, err := config.Retirements.CreateDraft(request.Context(), input, principal)
		if err != nil {
			app.operationFailure(w, operation, requestID, err)
			return
		}
		app.operationSuccess(w, operation, requestID, true, value.StateRevision, value.RecoveryEpoch, value)
	}
}
