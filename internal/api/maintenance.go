package api

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/principal"
	"github.com/vegastack/vegastack-labs/internal/result"
	"net/http"
)

type MaintenanceOperations struct {
	Diagnose     func(context.Context, string) (generated.MaintenanceDiagnosis, error)
	Prepare      func(context.Context, generated.MaintenanceDraftRequest, string) (generated.DeclarationRevisionRequest, error)
	Declarations DeclarationService
	Results      *result.Factory
}

func RegisterMaintenanceOperations(app *Application, c MaintenanceOperations) error {
	if app == nil || c.Diagnose == nil || c.Prepare == nil || c.Declarations == nil || c.Results == nil || c.Results != app.config.Results {
		return apiFailure(generated.ErrorCodeInputInvalid, "maintenance-config")
	}
	before := len(app.routes)
	app.routes = append(app.routes, route{id: "api.v1.maintenance.diagnose", method: http.MethodGet, pattern: "/api/v1/maintenance/hosts/{hostID}", deferredAuthorization: true, handler: app.maintenanceDiagnose(c)}, route{id: "api.v1.maintenance.drafts.create", method: http.MethodPost, pattern: "/api/v1/maintenance/drafts", deferredAuthorization: true, handler: app.maintenanceDraft(c)})
	if !routesAreGeneratedSubset(app.routes) {
		app.routes = app.routes[:before]
		return apiFailure(generated.ErrorCodeIntegrityFailure, "endpoint-registry")
	}
	return nil
}
func (app *Application) maintenanceDiagnose(c MaintenanceOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, p map[string]string) {
		const op = "api.v1.maintenance.diagnose"
		id := p["hostID"]
		if !principal.ValidID(id) || r.URL.RawQuery != "" {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "maintenance-query"))
			return
		}
		if _, e := app.authorizeAction(r, authorization.ActionRead, authorization.Target{Capability: "host.read", ResourceKind: "host", ResourceID: id}); e != nil {
			app.failure(w, op, e)
			return
		}
		d, e := c.Diagnose(r.Context(), id)
		if e != nil {
			app.failure(w, op, e)
			return
		}
		app.success(w, op, d.StateRevision, d.RecoveryEpoch, d)
	}
}
func (app *Application) maintenanceDraft(c MaintenanceOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const op = "api.v1.maintenance.drafts.create"
		var q generated.MaintenanceDraftRequest
		if e := decodeOperationRequest(r, 32768, []string{"schema", "schemaVersion", "declarationId", "expectedRevision", "expectedStateRevision", "recoveryEpoch", "action", "targetIds", "canaryHostId", "reasonDigest"}, &q, "canaryRunId", "incident"); e != nil {
			app.failure(w, op, e)
			return
		}
		raw, _ := json.Marshal(q)
		if generated.ValidateContractJSON(generated.SchemaIDMaintenanceDraftRequest, raw, generated.ContractExact) != nil {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "maintenance-request"))
			return
		}
		actor, ok := identity.PrincipalFromContext(r.Context())
		if !ok {
			app.failure(w, op, apiFailure(generated.ErrorCodeAuthenticationRequired, "principal"))
			return
		}
		targets := []authorization.Target{{Capability: "declaration.author", ResourceKind: "declaration", ResourceID: q.DeclarationID}}
		for _, id := range q.TargetIDs {
			targets = append(targets, authorization.Target{Capability: "maintenance.prepare", ResourceKind: "host", ResourceID: id})
		}
		if q.CanaryRunID != "" {
			if _, e := app.authorizeAction(r, authorization.ActionRead, authorization.Target{Capability: "run.read", ResourceKind: "run", ResourceID: q.CanaryRunID}); e != nil {
				app.failure(w, op, e)
				return
			}
		}
		for _, t := range targets {
			if _, e := app.authorizeAction(r, authorization.ActionAuthor, t); e != nil {
				app.failure(w, op, e)
				return
			}
		}
		session, e := c.Results.RequestID()
		if e != nil {
			app.failure(w, op, e)
			return
		}
		prepared, e := c.Prepare(r.Context(), q, session)
		if e != nil {
			app.operationFailure(w, op, session, e)
			return
		}
		// The protected server derives all observations; the public request cannot
		// substitute prerequisite success or executable operations.
		if prepared.DeclarationID != q.DeclarationID || prepared.Maintenance == nil || prepared.Maintenance.ExecutionAvailable {
			app.operationFailure(w, op, session, apiFailure(generated.ErrorCodeIntegrityFailure, "maintenance-draft"))
			return
		}
		author := change.AuthorScope{PrincipalID: actor.ID, PrincipalMethod: actor.Method, AgentSessionID: session}
		if identity.EffectivePrincipalKind(actor) == identity.PrincipalAgent {
			author.AgentName = actor.ID
		}
		revised, e := c.Declarations.Revise(r.Context(), author, prepared)
		if e != nil {
			app.operationFailure(w, op, session, e)
			return
		}
		app.operationSuccess(w, op, session, revised.Changed, revised.Document.StateRevision, revised.Document.RecoveryEpoch, revised.Document)
	}
}
