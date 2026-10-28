package api

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"net/http"
)

// Controller setup is a finite local-admin path, never an external executor or
// browser mutation endpoint. The lifecycle validates the typed fixed artifact.
type ControllerSetupLifecycle interface {
	Validate(context.Context, generated.Plan, string) (generated.ControllerSetupPilotPolicy, error)
	Claim(context.Context, generated.Plan, generated.Run, string, identity.Principal) (generated.ControllerSetupClaim, error)
	SubmitReceipt(context.Context, generated.ControllerSetupReceiptRequest, identity.Principal) (generated.Run, error)
}
type ControllerSetupOperations struct {
	Runs      RunOperationConfig
	Lifecycle ControllerSetupLifecycle
}

func RegisterControllerSetupOperations(app *Application, c ControllerSetupOperations) error {
	if app == nil || c.Lifecycle == nil || c.Runs.Runs == nil || c.Runs.Plans == nil || c.Runs.Results != app.config.Results {
		return apiFailure(generated.ErrorCodeInputInvalid, "controller-setup-config")
	}
	app.routes = append(app.routes,
		route{id: "api.v1.controller-setup.claim", method: http.MethodPost, pattern: "/api/v1/controller-setup/claim", deferredAuthorization: true, handler: app.controllerSetupClaim(c)},
		route{id: "api.v1.controller-setup.receipt", method: http.MethodPost, pattern: "/api/v1/controller-setup/receipt", deferredAuthorization: true, handler: app.controllerSetupReceipt(c)})
	if !routesAreGeneratedSubset(app.routes) {
		app.routes = app.routes[:len(app.routes)-2]
		return apiFailure(generated.ErrorCodeIntegrityFailure, "controller-setup-endpoints")
	}
	return nil
}
func controllerSetupLocalPrincipal(r *http.Request) (identity.Principal, error) {
	p, ok := identity.PrincipalFromContext(r.Context())
	if !ok || !identity.ValidPrincipal(p) || p.Method != identity.LocalOSPeerMethod || identity.EffectivePrincipalKind(p) != identity.PrincipalHuman {
		return p, apiFailure(generated.ErrorCodeAuthorizationDenied, "controller-setup-local-admin")
	}
	return p, nil
}
func (app *Application) controllerSetupClaim(c ControllerSetupOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const op = "api.v1.controller-setup.claim"
		principal, e := controllerSetupLocalPrincipal(r)
		if e != nil {
			app.failure(w, op, e)
			return
		}
		var q generated.ControllerSetupClaimRequest
		if e = decodeOperationRequest(r, 65536, []string{"schema", "schemaVersion", "reference", "inputJson"}, &q); e != nil {
			app.failure(w, op, e)
			return
		}
		if !exactGeneratedContract(generated.SchemaIDControllerSetupClaimRequest, q) || r.URL.RawQuery != "" {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "controller-setup-claim"))
			return
		}
		stored, e := c.Runs.Plans.GetPlan(r.Context(), q.Reference.PlanID)
		if e != nil {
			app.failure(w, op, e)
			return
		}
		if stored.Plan.PlanDigest != q.Reference.PlanDigest || stored.Plan.Binding.RecoveryEpoch != q.Reference.RecoveryEpoch {
			app.failure(w, op, apiFailure(generated.ErrorCodePlanStale, "controller-setup-plan"))
			return
		}
		policy, e := c.Lifecycle.Validate(r.Context(), stored.Plan, q.InputJSON)
		if e != nil {
			app.failure(w, op, e)
			return
		}
		if principal.ID != policy.AdministratorPrincipalID {
			app.failure(w, op, apiFailure(generated.ErrorCodeAuthorizationDenied, "controller-setup-admin"))
			return
		}
		decision, e := app.authorizeRunPlan(r, stored.Plan)
		if e != nil {
			app.failure(w, op, e)
			return
		}
		// Reuse the ordinary exact submit lane and current server-owned Slack proof.
		// The supplied Runs implementation defers only the closed controller class.
		run, e := app.submitExactPlan(r, c.Runs, stored.Plan, decision, q.Reference, "")
		if e != nil {
			app.failure(w, op, e)
			return
		}
		claim, e := c.Lifecycle.Claim(r.Context(), stored.Plan, run, q.InputJSON, principal)
		if e != nil {
			app.failure(w, op, e)
			return
		}
		app.success(w, op, claim.Run.StateRevision, claim.Run.RecoveryEpoch, claim)
	}
}
func (app *Application) controllerSetupReceipt(c ControllerSetupOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const op = "api.v1.controller-setup.receipt"
		principal, e := controllerSetupLocalPrincipal(r)
		if e != nil {
			app.failure(w, op, e)
			return
		}
		var q generated.ControllerSetupReceiptRequest
		if e = decodeOperationRequest(r, 65536, []string{"schema", "schemaVersion", "claimDigest", "runId", "leaseId", "recoveryEpoch", "inputJson", "resultDigest", "status"}, &q); e != nil {
			app.failure(w, op, e)
			return
		}
		if !exactGeneratedContract(generated.SchemaIDControllerSetupReceiptRequest, q) || r.URL.RawQuery != "" {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "controller-setup-receipt"))
			return
		}
		current, e := c.Runs.Runs.Get(r.Context(), q.RunID)
		if e != nil {
			app.failure(w, op, e)
			return
		}
		stored, e := c.Runs.Plans.GetPlan(r.Context(), current.PlanID)
		if e != nil {
			app.failure(w, op, e)
			return
		}
		if _, e = app.authorizeRunPlan(r, stored.Plan); e != nil {
			app.failure(w, op, e)
			return
		}
		result, e := c.Lifecycle.SubmitReceipt(r.Context(), q, principal)
		if e != nil {
			app.failure(w, op, e)
			return
		}
		app.success(w, op, result.StateRevision, result.RecoveryEpoch, result)
	}
}
