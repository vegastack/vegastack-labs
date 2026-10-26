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

type ServiceDeploymentOperations struct {
	Deployments  *store.DeploymentRepository
	Declarations *change.Service
	Results      *result.Factory
	Prepare      func(context.Context, generated.ServiceDeploymentDraftRequest) (generated.ServiceDeploymentRequest, error)
}

func RegisterServiceDeploymentOperations(app *Application, c ServiceDeploymentOperations) error {
	if app == nil || c.Deployments == nil || c.Declarations == nil || c.Results == nil || c.Results != app.config.Results || c.Prepare == nil {
		return apiFailure(generated.ErrorCodeInputInvalid, "service-deployment-config")
	}
	before := len(app.routes)
	app.routes = append(app.routes, route{id: "api.v1.services.deployment-drafts.create", method: http.MethodPost, pattern: "/api/v1/services/deployment-drafts", deferredAuthorization: true, handler: app.serviceDeploymentDraft(c)}, route{id: "api.v1.services.deployment.get", method: http.MethodGet, pattern: "/api/v1/services/{serviceID}/deployment", deferredAuthorization: true, handler: app.serviceDeploymentRead(c)})
	if !routesAreGeneratedSubset(app.routes) {
		app.routes = app.routes[:before]
		return apiFailure(generated.ErrorCodeIntegrityFailure, "endpoint-registry")
	}
	return nil
}
func (app *Application) serviceDeploymentDraft(c ServiceDeploymentOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const op = "api.v1.services.deployment-drafts.create"
		var input generated.ServiceDeploymentDraftRequest
		if err := decodeOperationRequest(r, 16384, []string{"schema", "schemaVersion", "serviceId", "artifactId", "action", "expectedStateRevision", "recoveryEpoch", "idempotencyKey", "reasonDigest"}, &input); err != nil {
			app.failure(w, op, err)
			return
		}
		raw, _ := json.Marshal(input)
		if generated.ValidateContractJSON(generated.SchemaIDServiceDeploymentDraftRequest, raw, generated.ContractExact) != nil {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "service-request"))
			return
		}
		if _, err := app.authorizeAction(r, authorization.ActionAuthor, authorization.Target{Capability: "service.deploy.prepare", ResourceKind: "service", ResourceID: input.ServiceID}); err != nil {
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
		if prepared.Definition.ServiceID != input.ServiceID || prepared.Artifact.ArtifactID != input.ArtifactID || prepared.Action != input.Action || prepared.ExpectedStateRevision != input.ExpectedStateRevision || prepared.RecoveryEpoch != input.RecoveryEpoch || prepared.IdempotencyKey != input.IdempotencyKey || prepared.ReasonDigest != input.ReasonDigest {
			app.failure(w, op, apiFailure(generated.ErrorCodeIntegrityFailure, "service-request"))
			return
		}
		draft, err := c.Deployments.Stage(r.Context(), prepared)
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

func (app *Application) serviceDeploymentRead(c ServiceDeploymentOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, params map[string]string) {
		const op = "api.v1.services.deployment.get"
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
		record, err := c.Deployments.Get(r.Context(), id)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		app.success(w, op, scope.StateRevision, scope.RecoveryEpoch, record)
	}
}
