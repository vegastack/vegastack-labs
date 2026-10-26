package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/principal"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type ServiceRecoveryOperations struct {
	Recoveries   *store.ServiceRecoveryRepository
	Declarations *change.Service
	Results      *result.Factory
	Prepare      func(context.Context, generated.ServiceRecoveryDraftRequest) (generated.ServiceRecoveryRequest, error)
}

func RegisterServiceRecoveryOperations(app *Application, c ServiceRecoveryOperations) error {
	if app == nil || c.Recoveries == nil || c.Declarations == nil || c.Results == nil || c.Results != app.config.Results || c.Prepare == nil {
		return apiFailure(generated.ErrorCodeInputInvalid, "service-recovery-config")
	}
	before := len(app.routes)
	app.routes = append(app.routes, route{id: "api.v1.services.recovery-drafts.create", method: http.MethodPost, pattern: "/api/v1/services/recovery-drafts", deferredAuthorization: true, handler: app.serviceRecoveryDraft(c)}, route{id: "api.v1.services.recovery.get", method: http.MethodGet, pattern: "/api/v1/services/{serviceID}/recovery", deferredAuthorization: true, handler: app.serviceRecoveryRead(c)})
	if !routesAreGeneratedSubset(app.routes) {
		app.routes = app.routes[:before]
		return apiFailure(generated.ErrorCodeIntegrityFailure, "endpoint-registry")
	}
	return nil
}
func (app *Application) serviceRecoveryDraft(c ServiceRecoveryOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const op = "api.v1.services.recovery-drafts.create"
		var input generated.ServiceRecoveryDraftRequest
		if err := decodeOperationRequest(r, 16384, []string{"schema", "schemaVersion", "serviceId", "policyId", "backupPointId", "action", "expectedStateRevision", "recoveryEpoch", "idempotencyKey", "reasonDigest"}, &input); err != nil {
			app.failure(w, op, err)
			return
		}
		raw, _ := json.Marshal(input)
		if generated.ValidateContractJSON(generated.SchemaIDServiceRecoveryDraftRequest, raw, generated.ContractExact) != nil {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "service-request"))
			return
		}
		if _, err := app.authorizeAction(r, authorization.ActionAuthor, authorization.Target{Capability: "service.recovery.prepare", ResourceKind: "service", ResourceID: input.ServiceID}); err != nil {
			app.failure(w, op, err)
			return
		}
		// Preparation checks current repository scope before borrowing protected
		// provider credentials; Stage checks it again after the observation.
		prepared, err := c.Prepare(r.Context(), input)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		if prepared.Definition.ServiceID != input.ServiceID || prepared.Binding.PolicyID != input.PolicyID || prepared.BackupPointID != input.BackupPointID || prepared.Action != input.Action || prepared.ExpectedStateRevision != input.ExpectedStateRevision || prepared.RecoveryEpoch != input.RecoveryEpoch || prepared.IdempotencyKey != input.IdempotencyKey || prepared.ReasonDigest != input.ReasonDigest {
			app.failure(w, op, apiFailure(generated.ErrorCodeIntegrityFailure, "service-request"))
			return
		}
		draft, err := c.Recoveries.Stage(r.Context(), prepared)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		actor, ok := identity.PrincipalFromContext(r.Context())
		if !ok {
			app.failure(w, op, apiFailure(generated.ErrorCodeAuthenticationRequired, "principal"))
			return
		}
		requestID, err := c.Results.RequestID()
		if err != nil {
			app.failure(w, op, err)
			return
		}
		author := change.AuthorScope{PrincipalID: actor.ID, PrincipalMethod: actor.Method, AgentSessionID: requestID}
		if identity.EffectivePrincipalKind(actor) == identity.PrincipalAgent {
			author.AgentName = actor.ID
		}
		revised, err := c.Declarations.Revise(r.Context(), author, draft)
		if err != nil {
			app.operationFailure(w, op, requestID, err)
			return
		}
		app.operationSuccess(w, op, requestID, revised.Changed, revised.Document.StateRevision, revised.Document.RecoveryEpoch, revised.Document)
	}
}

func (app *Application) serviceRecoveryRead(c ServiceRecoveryOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, params map[string]string) {
		const op = "api.v1.services.recovery.get"
		id := params["serviceID"]
		if r.URL.RawQuery != "" || !principal.ValidID(id) {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "service-query"))
			return
		}
		scope, err := app.authorizeAction(r, authorization.ActionRead, authorization.Target{Capability: "service.read", ResourceKind: "service", ResourceID: id})
		if err != nil {
			app.failure(w, op, err)
			return
		}
		record, err := c.Recoveries.Get(r.Context(), id)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		app.success(w, op, scope.StateRevision, scope.RecoveryEpoch, record)
	}
}
