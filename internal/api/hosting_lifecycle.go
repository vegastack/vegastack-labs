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

type HostingLifecycleOperations struct {
	Lifecycles   *store.HostingLifecycleRepository
	Declarations *change.Service
	Results      *result.Factory
	Prepare      func(context.Context, generated.HostingLifecycleDraftRequest) (generated.HostingLifecycleRequest, error)
}

func RegisterHostingLifecycleOperations(app *Application, c HostingLifecycleOperations) error {
	if app == nil || c.Lifecycles == nil || c.Declarations == nil || c.Results == nil || c.Results != app.config.Results || c.Prepare == nil {
		return apiFailure(generated.ErrorCodeInputInvalid, "hosting-lifecycle-config")
	}
	before := len(app.routes)
	app.routes = append(app.routes, route{id: "api.v1.hosting.lifecycle-drafts.create", method: http.MethodPost, pattern: "/api/v1/hosting/lifecycle-drafts", deferredAuthorization: true, handler: app.hostingLifecycleDraft(c)}, route{id: "api.v1.hosting.lifecycle.get", method: http.MethodGet, pattern: "/api/v1/hosting/{targetID}/lifecycle", deferredAuthorization: true, handler: app.hostingLifecycleRead(c)})
	if !routesAreGeneratedSubset(app.routes) {
		app.routes = app.routes[:before]
		return apiFailure(generated.ErrorCodeIntegrityFailure, "endpoint-registry")
	}
	return nil
}
func (app *Application) hostingLifecycleDraft(c HostingLifecycleOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const op = "api.v1.hosting.lifecycle-drafts.create"
		var input generated.HostingLifecycleDraftRequest
		if err := decodeOperationRequest(r, 16384, []string{"schema", "schemaVersion", "targetId", "action", "expectedStateRevision", "recoveryEpoch", "idempotencyKey", "reasonDigest"}, &input); err != nil {
			app.failure(w, op, err)
			return
		}
		raw, _ := json.Marshal(input)
		if generated.ValidateContractJSON(generated.SchemaIDHostingLifecycleDraftRequest, raw, generated.ContractExact) != nil {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "service-request"))
			return
		}
		if _, err := app.authorizeAction(r, authorization.ActionAuthor, authorization.Target{Capability: "hosting.lifecycle.prepare", ResourceKind: "hosting", ResourceID: input.TargetID}); err != nil {
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
		if prepared.TargetID != input.TargetID || prepared.Action != input.Action || prepared.ExpectedStateRevision != input.ExpectedStateRevision || prepared.RecoveryEpoch != input.RecoveryEpoch || prepared.IdempotencyKey != input.IdempotencyKey || prepared.ReasonDigest != input.ReasonDigest {
			app.failure(w, op, apiFailure(generated.ErrorCodeIntegrityFailure, "service-request"))
			return
		}
		draft, err := c.Lifecycles.Stage(r.Context(), prepared)
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

func (app *Application) hostingLifecycleRead(c HostingLifecycleOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, params map[string]string) {
		const op = "api.v1.hosting.lifecycle.get"
		id := params["targetID"]
		if r.URL.RawQuery != "" || !principal.ValidID(id) {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "service-query"))
			return
		}
		scope, err := app.authorizeAction(r, authorization.ActionRead, authorization.Target{Capability: "hosting.read", ResourceKind: "hosting", ResourceID: id})
		if err != nil {
			app.failure(w, op, err)
			return
		}
		record, err := c.Lifecycles.Get(r.Context(), id)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		app.success(w, op, scope.StateRevision, scope.RecoveryEpoch, record)
	}
}
