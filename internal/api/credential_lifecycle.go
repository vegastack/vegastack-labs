package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/result"
)

type CredentialLifecycleOperations struct {
	Lifecycle CredentialLifecycleService
	Results   *result.Factory
}

func RegisterCredentialLifecycleOperation(app *Application, config CredentialLifecycleOperations) error {
	if app == nil || config.Lifecycle == nil || config.Results == nil || config.Results != app.config.Results {
		return apiFailure(generated.ErrorCodeInputInvalid, "credential-lifecycle-config")
	}
	app.routes = append(app.routes, route{id: "api.v1.credential-lifecycle-drafts.create", method: http.MethodPost, pattern: "/api/v1/credential-lifecycle-drafts", deferredAuthorization: true, handler: app.credentialLifecycleDraft(config)})
	if !routesAreGeneratedSubset(app.routes) {
		app.routes = app.routes[:len(app.routes)-1]
		return apiFailure(generated.ErrorCodeIntegrityFailure, "endpoint-registry")
	}
	return nil
}

func (app *Application) credentialLifecycleDraft(config CredentialLifecycleOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const op = "api.v1.credential-lifecycle-drafts.create"
		principal, ok := identity.PrincipalFromContext(r.Context())
		if !ok || principal.Method != identity.LocalOSPeerMethod {
			app.failure(w, op, apiFailure(generated.ErrorCodeAuthorizationDenied, "credential-operator-only"))
			return
		}
		if r.URL.RawQuery != "" {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "credential-lifecycle-query"))
			return
		}
		var input generated.CredentialLifecycleRequest
		fields := []string{"schema", "schemaVersion", "expectedStateRevision", "recoveryEpoch", "targetDigest", "idempotencyKey", "action", "draftId", "referenceId", "consumerIds", "requiredDeniedConsumerIds", "nativeConsumers", "nativeDeniedReaders", "materialVersion", "priorMaterialVersion", "resolverId", "targetId", "overlapSeconds", "priorRecoveryEpoch", "custodyProofDigest", "formerControllerFenceDigest"}
		if err := decodeOperationRequest(r, 262144, fields, &input); err != nil {
			app.failure(w, op, err)
			return
		}
		raw, err := json.Marshal(input)
		if err != nil || generated.ValidateContractJSON(generated.SchemaIDCredentialLifecycleRequest, raw, generated.ContractExact) != nil {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "credential-lifecycle-contract"))
			return
		}
		if _, err := app.authorizeAction(r, authorization.ActionAuthor, authorization.Target{Capability: "credential.lifecycle.author", ResourceKind: "credential-reference", ResourceID: input.ReferenceID}); err != nil {
			app.failure(w, op, err)
			return
		}
		requestID, err := config.Results.RequestID()
		if err != nil {
			app.failure(w, op, err)
			return
		}
		var value generated.CredentialLifecycleSubmission
		changed := true
		if detailed, ok := config.Lifecycle.(interface {
			createDraftResult(context.Context, generated.CredentialLifecycleRequest, identity.Principal) (generated.CredentialLifecycleSubmission, bool, error)
		}); ok {
			value, changed, err = detailed.createDraftResult(r.Context(), input, principal)
		} else {
			value, err = config.Lifecycle.CreateDraft(r.Context(), input, principal)
		}
		if err != nil {
			app.operationFailure(w, op, requestID, err)
			return
		}
		encoded, err := json.Marshal(value)
		if err != nil || generated.ValidateContractJSON(generated.SchemaIDCredentialLifecycleSubmission, encoded, generated.ContractExact) != nil || value.Action != input.Action || value.ReferenceID != input.ReferenceID || value.Status != "draft" || value.RecoveryEpoch != input.RecoveryEpoch || value.StateRevision != input.ExpectedStateRevision+2 {
			app.operationFailure(w, op, requestID, apiFailure(generated.ErrorCodeIntegrityFailure, "credential-lifecycle-submission"))
			return
		}
		app.operationSuccess(w, op, requestID, changed, value.StateRevision, value.RecoveryEpoch, value)
	}
}
