package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/principal"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type ServicesOperations struct {
	Services     *store.ServiceRepository
	Declarations *change.Service
	Results      *result.Factory
	Prepare      func(context.Context, generated.ServiceImportDraftRequest) (generated.ServiceImportRequest, error)
	Observe      func(context.Context, string) (generated.ServiceObservation, error)
}

func RegisterServiceOperations(app *Application, c ServicesOperations) error {
	if app == nil || c.Services == nil || c.Declarations == nil || c.Results == nil || c.Results != app.config.Results || c.Prepare == nil || c.Observe == nil {
		return apiFailure(generated.ErrorCodeInputInvalid, "service-config")
	}
	before := len(app.routes)
	app.routes = append(app.routes,
		route{id: "api.v1.services.import-drafts.create", method: http.MethodPost, pattern: "/api/v1/services/import-drafts", deferredAuthorization: true, handler: app.serviceImportDraft(c)},
		route{id: "api.v1.services.list", method: http.MethodGet, pattern: "/api/v1/services", deferredAuthorization: true, handler: app.serviceList(c)},
		route{id: "api.v1.services.get", method: http.MethodGet, pattern: "/api/v1/services/{serviceID}", deferredAuthorization: true, handler: app.serviceRead(c, false)},
		route{id: "api.v1.services.observation.get", method: http.MethodGet, pattern: "/api/v1/services/{serviceID}/observation", deferredAuthorization: true, handler: app.serviceRead(c, true)})
	if !routesAreGeneratedSubset(app.routes) {
		app.routes = app.routes[:before]
		return apiFailure(generated.ErrorCodeIntegrityFailure, "endpoint-registry")
	}
	return nil
}

func (app *Application) serviceImportDraft(c ServicesOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const op = "api.v1.services.import-drafts.create"
		var input generated.ServiceImportDraftRequest
		if err := decodeOperationRequest(r, 16384, []string{"schema", "schemaVersion", "serviceId", "bindingId", "expectedStateRevision", "recoveryEpoch", "idempotencyKey", "reasonDigest"}, &input); err != nil {
			app.failure(w, op, err)
			return
		}
		raw, _ := json.Marshal(input)
		if generated.ValidateContractJSON(generated.SchemaIDServiceImportDraftRequest, raw, generated.ContractExact) != nil {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "service-request"))
			return
		}
		if _, err := app.authorizeAction(r, authorization.ActionAuthor, authorization.Target{Capability: "service.import.prepare", ResourceKind: "service", ResourceID: input.ServiceID}); err != nil {
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
		if prepared.Definition.ServiceID != input.ServiceID || prepared.Definition.BindingID != input.BindingID || prepared.ExpectedStateRevision != input.ExpectedStateRevision || prepared.RecoveryEpoch != input.RecoveryEpoch || prepared.IdempotencyKey != input.IdempotencyKey || prepared.ReasonDigest != input.ReasonDigest {
			app.failure(w, op, apiFailure(generated.ErrorCodeIntegrityFailure, "service-request"))
			return
		}
		draft, err := c.Services.Stage(r.Context(), prepared)
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

func serviceListQuery(raw string) (string, int, error) {
	values, err := url.ParseQuery(raw)
	if err != nil {
		return "", 0, apiFailure(generated.ErrorCodeInputInvalid, "service-query")
	}
	after, limit := "", 50
	for key, v := range values {
		if len(v) != 1 {
			return "", 0, apiFailure(generated.ErrorCodeInputInvalid, "service-query")
		}
		switch key {
		case "after":
			if !principal.ValidID(v[0]) {
				return "", 0, apiFailure(generated.ErrorCodeInputInvalid, "service-query")
			}
			after = v[0]
		case "limit":
			n, e := strconv.Atoi(v[0])
			if e != nil || n < 1 || n > 100 || strconv.Itoa(n) != v[0] {
				return "", 0, apiFailure(generated.ErrorCodeInputInvalid, "service-query")
			}
			limit = n
		default:
			return "", 0, apiFailure(generated.ErrorCodeInputInvalid, "service-query")
		}
	}
	return after, limit, nil
}

func (app *Application) serviceList(c ServicesOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const op = "api.v1.services.list"
		after, limit, err := serviceListQuery(r.URL.RawQuery)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		// List evaluates exact service grants in the current store snapshot rather
		// than requiring a wildcard grant or querying private records then filtering.
		value, err := c.Services.List(r.Context(), after, limit)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		app.success(w, op, value.StateRevision, value.RecoveryEpoch, value)
	}
}

func (app *Application) serviceRead(c ServicesOperations, observe bool) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, params map[string]string) {
		op := "api.v1.services.get"
		if observe {
			op = "api.v1.services.observation.get"
		}
		id := params["serviceID"]
		if r.URL.RawQuery != "" || !principal.ValidID(id) {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "service-query"))
			return
		}
		if _, err := app.authorizeAction(r, authorization.ActionRead, authorization.Target{Capability: "service.read", ResourceKind: "service", ResourceID: id}); err != nil {
			app.failure(w, op, err)
			return
		}
		// Repository reads recheck principal/device/grants and protected binding.
		record, err := c.Services.Get(r.Context(), id)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		if !observe {
			app.success(w, op, record.StateRevision, record.RecoveryEpoch, record)
			return
		}
		observation, err := c.Observe(r.Context(), id)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		app.success(w, op, observation.StateRevision, observation.RecoveryEpoch, observation)
	}
}
