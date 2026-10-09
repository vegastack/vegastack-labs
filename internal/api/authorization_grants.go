package api

import (
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/store"
	"net/http"
)

type AuthorizationGrantOperations struct {
	Grants       *store.GrantBatchRepository
	Declarations *change.Service
	Results      *result.Factory
}

func RegisterAuthorizationGrantOperations(app *Application, c AuthorizationGrantOperations) error {
	if app == nil || c.Grants == nil || c.Declarations == nil || c.Results == nil || c.Results != app.config.Results {
		return apiFailure(generated.ErrorCodeInputInvalid, "grant-config")
	}
	app.routes = append(app.routes, route{id: "api.v1.authorization.grant-batches.create", method: http.MethodPost, pattern: "/api/v1/authorization/grant-batches", deferredAuthorization: true, handler: app.grantBatchDraft(c)})
	if !routesAreGeneratedSubset(app.routes) {
		app.routes = app.routes[:len(app.routes)-1]
		return apiFailure(generated.ErrorCodeIntegrityFailure, "endpoint-registry")
	}
	return nil
}
func (app *Application) grantBatchDraft(c AuthorizationGrantOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const op = "api.v1.authorization.grant-batches.create"
		var input generated.AuthorizationGrantBatchRequest
		if err := decodeOperationRequest(r, 32768, []string{"schema", "schemaVersion", "principalId", "expectedGrantRevision", "expectedDeclarationRevision", "expectedStateRevision", "recoveryEpoch", "idempotencyKey", "reasonDigest", "changes"}, &input); err != nil {
			app.failure(w, op, err)
			return
		}
		if err := store.ValidateAuthorizationGrantBatch(input); err != nil {
			app.failure(w, op, err)
			return
		}
		if _, err := app.authorizeAction(r, authorization.ActionAuthor, authorization.Target{Capability: "authorization.policy.write", ResourceKind: "authorization-policy", ResourceID: input.PrincipalID}); err != nil {
			app.failure(w, op, err)
			return
		}
		principal, ok := identity.PrincipalFromContext(r.Context())
		if !ok {
			app.failure(w, op, apiFailure(generated.ErrorCodeAuthenticationRequired, "principal"))
			return
		}
		draft, err := c.Grants.Stage(r.Context(), input)
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
