package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type CredentialLifecycleService interface {
	CreateDraft(context.Context, generated.CredentialLifecycleRequest, identity.Principal) (generated.CredentialLifecycleSubmission, error)
}

type credentialLifecycleService struct {
	references   *store.CredentialRepository
	revisions    *store.PlanRepository
	declarations *change.Service
	authorizer   EffectiveAuthorizer
}

func NewCredentialLifecycleService(references *store.CredentialRepository, revisions *store.PlanRepository, declarations *change.Service, authorizer EffectiveAuthorizer) (CredentialLifecycleService, error) {
	if references == nil || revisions == nil || declarations == nil || authorizer == nil {
		return nil, apiFailure(generated.ErrorCodeInputInvalid, "credential-lifecycle-config")
	}
	return &credentialLifecycleService{references, revisions, declarations, authorizer}, nil
}

func lifecycleMetadataDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (service *credentialLifecycleService) CreateDraft(ctx context.Context, input generated.CredentialLifecycleRequest, principal identity.Principal) (generated.CredentialLifecycleSubmission, error) {
	submission, _, err := service.createDraftResult(ctx, input, principal)
	return submission, err
}

func (service *credentialLifecycleService) createDraftResult(ctx context.Context, input generated.CredentialLifecycleRequest, principal identity.Principal) (generated.CredentialLifecycleSubmission, bool, error) {
	var zero generated.CredentialLifecycleSubmission
	if !identity.ValidPrincipal(principal) || principal.Method != identity.LocalOSPeerMethod || identity.EffectivePrincipalKind(principal) != identity.PrincipalHuman {
		return zero, false, apiFailure(generated.ErrorCodeAuthorizationDenied, "credential-operator-only")
	}
	target := authorization.Target{Capability: "credential.lifecycle.author", ResourceKind: "credential-reference", ResourceID: input.ReferenceID}
	decision, err := service.authorizer.Authorize(ctx, principal, authorization.Request{Action: authorization.ActionAuthor, Target: target})
	if err != nil || decision.PrincipalID != principal.ID || decision.Action != authorization.ActionAuthor || decision.Target != target || !decision.Allowed {
		return zero, false, apiFailure(generated.ErrorCodeAuthorizationDenied, "credential-lifecycle-author")
	}
	raw, err := json.Marshal(input)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDCredentialLifecycleRequest, raw, generated.ContractExact) != nil || input.TargetDigest == "" || credentialref.LifecycleTargetDigest(input) != input.TargetDigest {
		return zero, false, apiFailure(generated.ErrorCodeInputInvalid, "credential-lifecycle-request")
	}
	current, err := service.revisions.CurrentRevision(ctx)
	if err != nil {
		return zero, false, err
	}
	if current.RecoveryEpoch != input.RecoveryEpoch {
		return zero, false, apiFailure(generated.ErrorCodeRecoveryEpochMismatch, "credential-lifecycle-epoch")
	}
	requestDigest := lifecycleMetadataDigest("credential-lifecycle-request-v1\x00" + principal.ID + "\x00" + string(raw))
	keyDigest := lifecycleMetadataDigest("credential-lifecycle-key-v1\x00" + principal.ID + "\x00" + input.IdempotencyKey)
	changeID := "credential-change-" + keyDigest[7:39]
	operationID := "credential-operation-" + keyDigest[7:39]
	binding := credentialref.LifecycleBinding{OperationID: operationID, Action: credentialref.LifecycleAction(input.Action), DraftID: input.DraftID, ReferenceID: input.ReferenceID, ConsumerIDs: input.ConsumerIDs, RequiredDeniedConsumerIDs: input.RequiredDeniedConsumerIDs, MaterialVersion: input.MaterialVersion, PriorMaterialVersion: input.PriorMaterialVersion, ResolverID: input.ResolverID, TargetID: input.TargetID, OverlapSeconds: input.OverlapSeconds, StateRevision: input.ExpectedStateRevision + 3, RecoveryEpoch: input.RecoveryEpoch, PriorRecoveryEpoch: input.PriorRecoveryEpoch, CustodyProofDigest: input.CustodyProofDigest, FormerControllerFenceDigest: input.FormerControllerFenceDigest}
	if input.DraftID != nil {
		draft, lookupErr := service.references.GetImportDraftByID(ctx, *input.DraftID)
		if lookupErr != nil {
			return zero, false, lookupErr
		}
		binding.ImportDraftStateRevision, binding.ImportDraftConsumerID, binding.ImportDraftPurposeID = &draft.StateRevision, &draft.ConsumerID, &draft.PurposeID
		binding.CiphertextFingerprint = draft.CiphertextFingerprint
		if !draft.MatchesLifecycleBinding(binding) {
			return zero, false, apiFailure(generated.ErrorCodePrerequisiteBlocked, "credential-import-draft-exact-origin")
		}
	} else {
		version, lookupErr := service.references.GetCredentialVersion(ctx, input.ReferenceID, input.MaterialVersion)
		if lookupErr != nil {
			return zero, false, lookupErr
		}
		if version.TargetID != input.TargetID || version.ResolverID != input.ResolverID || version.RecoveryEpoch != input.RecoveryEpoch || input.Action == "credential.activate" && !slices.Contains(input.ConsumerIDs, version.ConsumerID) {
			return zero, false, apiFailure(generated.ErrorCodePrerequisiteBlocked, "credential-version-identity")
		}
		binding.CiphertextFingerprint = version.Fingerprint
	}
	manifest := credentialref.LifecycleManifestDigestOf(binding)
	if manifest == "" {
		return zero, false, apiFailure(generated.ErrorCodeInputInvalid, "credential-lifecycle-binding")
	}
	submission := generated.CredentialLifecycleSubmission{Schema: generated.SchemaIDCredentialLifecycleSubmission, SchemaVersion: "1.2.0", ChangeID: changeID, OperationID: operationID, ReferenceID: input.ReferenceID, Action: input.Action, Status: "draft", StateRevision: input.ExpectedStateRevision + 2, RecoveryEpoch: input.RecoveryEpoch}
	if existing, lookupErr := service.references.LookupLifecycleDraft(ctx, changeID, 1, operationID); lookupErr == nil {
		if credentialref.LifecycleManifestDigestOf(existing) != manifest {
			return zero, false, apiFailure(generated.ErrorCodeStateConflict, "credential-lifecycle-idempotency")
		}
		return submission, false, nil
	} else if store.Code(lookupErr) != generated.ErrorCodeResourceNotFound {
		return zero, false, lookupErr
	}
	if current.StateRevision != input.ExpectedStateRevision {
		// An interrupted first attempt may have persisted only the inert
		// declaration. Resume only that exact declaration/revision; its original
		// future execution revision is never shifted to fit newer state.
		if current.StateRevision != input.ExpectedStateRevision+1 {
			return zero, false, apiFailure(generated.ErrorCodePlanStale, "credential-lifecycle-revision")
		}
		existing, getErr := service.declarations.Get(ctx, changeID, 1)
		if getErr != nil || existing.Status != "draft" || existing.StateRevision != current.StateRevision || existing.RecoveryEpoch != current.RecoveryEpoch || len(existing.Extensions) != 1 || existing.Extensions[0].Name != "x-credential-lifecycle" || existing.Extensions[0].ValueDigest != manifest {
			return zero, false, apiFailure(generated.ErrorCodePlanStale, "credential-lifecycle-revision")
		}
	}
	declaration := generated.DeclarationRevisionRequest{Schema: generated.SchemaIDDeclarationRevisionRequest, SchemaVersion: "1.0.0", DeclarationID: changeID, DeclarationType: "credential.lifecycle", ExpectedRevision: 1, ExpectedStateRevision: input.ExpectedStateRevision, RecoveryEpoch: input.RecoveryEpoch, ReasonDigest: requestDigest, Operations: []generated.DeclarationOperation{{Sequence: 1, OperationID: operationID, OperationType: input.Action, AdapterID: "core.credential", TargetID: input.TargetID, InputDigest: binding.CiphertextFingerprint, ArtifactDigest: binding.CiphertextFingerprint, Idempotent: false}}, Extensions: []generated.ContractExtension{{Name: "x-credential-lifecycle", ValueDigest: manifest}}}
	draft, err := service.declarations.Revise(ctx, change.AuthorScope{PrincipalID: principal.ID, PrincipalMethod: principal.Method, AgentSessionID: "session-" + requestDigest[7:39]}, declaration)
	if err != nil {
		return zero, false, err
	}
	_, err = service.references.PutLifecycleDraft(ctx, store.CredentialLifecycleDraftRequest{DeclarationID: changeID, DeclarationRevision: 1, Binding: binding, Expected: store.RevisionToken{StateRevision: draft.Document.StateRevision, RecoveryEpoch: input.RecoveryEpoch}, Attribution: audit.Attribution{AuthenticatedPrincipalID: principal.ID, AuthenticatedPrincipalMethod: principal.Method}, KeyDigest: keyDigest, RequestDigest: requestDigest})
	if err != nil {
		return zero, false, err
	}
	return submission, true, nil
}
