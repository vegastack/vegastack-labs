package api

import (
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/networkconnect"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/store"
	"net/http"
)

type NetworkEndpointOperations struct {
	Endpoints    *store.NetworkEndpointRepository
	Declarations *change.Service
	Results      *result.Factory
}

func RegisterNetworkEndpointOperations(app *Application, c NetworkEndpointOperations) error {
	if app == nil || c.Endpoints == nil || c.Declarations == nil || c.Results == nil || c.Results != app.config.Results {
		return apiFailure(generated.ErrorCodeInputInvalid, "grant-config")
	}
	app.routes = append(app.routes, route{id: "api.v1.network.endpoint-drafts.create", method: http.MethodPost, pattern: "/api/v1/network/endpoint-drafts", deferredAuthorization: true, handler: app.networkEndpointDraft(c)}, route{id: "api.v1.hosts.connection-descriptor.get", method: http.MethodGet, pattern: "/api/v1/hosts/{hostID}/connection-descriptor", deferredAuthorization: true, handler: app.networkDescriptor(c)})
	if !routesAreGeneratedSubset(app.routes) {
		app.routes = app.routes[:len(app.routes)-2]
		return apiFailure(generated.ErrorCodeIntegrityFailure, "endpoint-registry")
	}
	return nil
}
func (app *Application) networkEndpointDraft(c NetworkEndpointOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const op = "api.v1.network.endpoint-drafts.create"
		var input generated.NetworkEndpointRequest
		if err := decodeOperationRequest(r, 16384, []string{"schema", "schemaVersion", "endpoint", "action", "expectedEndpointRevision", "expectedDeclarationRevision", "expectedStateRevision", "recoveryEpoch", "idempotencyKey", "reasonDigest"}, &input); err != nil {
			app.failure(w, op, err)
			return
		}
		if err := networkconnect.ValidateRequest(input); err != nil {
			app.failure(w, op, err)
			return
		}
		if _, err := app.authorizeAction(r, authorization.ActionAuthor, authorization.Target{Capability: "network.endpoint.write", ResourceKind: "host", ResourceID: input.Endpoint.HostID}); err != nil {
			app.failure(w, op, err)
			return
		}
		principal, ok := identity.PrincipalFromContext(r.Context())
		if !ok {
			app.failure(w, op, apiFailure(generated.ErrorCodeAuthenticationRequired, "principal"))
			return
		}
		draft, err := c.Endpoints.Stage(r.Context(), input)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		requestID, err := c.Results.RequestID()
		if err != nil {
			app.failure(w, op, err)
			return
		}
		author := change.AuthorScope{PrincipalID: principal.ID, PrincipalMethod: principal.Method, AgentSessionID: requestID}
		if identity.EffectivePrincipalKind(principal) == identity.PrincipalAgent {
			author.AgentName = principal.ID
		}
		revised, err := c.Declarations.Revise(r.Context(), author, draft)
		if err != nil {
			app.operationFailure(w, op, requestID, err)
			return
		}
		app.operationSuccess(w, op, requestID, revised.Changed, revised.Document.StateRevision, revised.Document.RecoveryEpoch, revised.Document)
	}
}

func (app *Application) networkDescriptor(c NetworkEndpointOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, params map[string]string) {
		const op = "api.v1.hosts.connection-descriptor.get"
		if r.URL.RawQuery != "" {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "network-query"))
			return
		}
		if _, err := app.authorizeAction(r, authorization.ActionRead, authorization.Target{Capability: "network.connect", ResourceKind: "host", ResourceID: params["hostID"]}); err != nil {
			app.failure(w, op, err)
			return
		}
		d, err := c.Endpoints.Descriptor(r.Context(), params["hostID"])
		if err != nil {
			app.failure(w, op, err)
			return
		}
		app.success(w, op, d.StateRevision, d.RecoveryEpoch, d)
	}
}
