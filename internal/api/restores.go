package api

import (
	"context"
	"net/http"
	"time"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/result"
)

// RestoreOperations is the already-authorized orchestration boundary. The
// implementation binds the authenticated principal to the immutable plan and
// acknowledgement before it changes recovery state.
type RestoreOperations interface {
	Plan(context.Context, generated.RestoreRequest, identity.Principal) (generated.RestoreBinding, error)
	Run(context.Context, generated.RestoreRunRequest, identity.Principal) (generated.RestoreBinding, error)
	Verify(context.Context, generated.RestoreVerifyRequest, identity.Principal) (generated.RestoreVerification, error)
	Get(context.Context, string) (generated.BrowserRestoreStatus, error)
	AuthorizationPlan(context.Context, string) (generated.Plan, error)
}

type RestoreConfig struct {
	Operations    RestoreOperations
	Results       *result.Factory
	Authorization EffectiveAuthorizationConfig
	MaxBodyBytes  int64
}

func RegisterRestoreOperations(app *Application, config RestoreConfig) error {
	if app == nil || config.Operations == nil || config.Results == nil || config.Results != app.config.Results || config.Authorization.Authorizer == nil || config.Authorization.Recorder == nil {
		return apiFailure(generated.ErrorCodeInputInvalid, "restore-config")
	}
	if config.Authorization.Clock == nil {
		config.Authorization.Clock = time.Now
	}
	if config.MaxBodyBytes == 0 {
		config.MaxBodyBytes = MaxOperationRequestBytes
	}
	if config.MaxBodyBytes < 1 || config.MaxBodyBytes > MaxOperationRequestBytes {
		return apiFailure(generated.ErrorCodeInputInvalid, "restore-limit")
	}
	previous := app.effective
	app.effective = config.Authorization
	app.routes = append(app.routes,
		route{id: "api.v1.restores.get", method: http.MethodGet, pattern: "/api/v1/restores/plans/{planId}", capability: "restore.read", kind: "restore-plan", handler: app.restoreGet(config)},
		route{id: "api.v1.restores.plan", method: http.MethodPost, pattern: "/api/v1/restores/plans", deferredAuthorization: true, handler: app.restorePlan(config)},
		route{id: "api.v1.restores.run", method: http.MethodPost, pattern: "/api/v1/restores/plans/{planId}/run", deferredAuthorization: true, handler: app.restoreRun(config)},
		route{id: "api.v1.restores.verify", method: http.MethodPost, pattern: "/api/v1/restores/plans/{planId}/verify", deferredAuthorization: true, handler: app.restoreVerify(config)},
	)
	if !routesAreGeneratedSubset(app.routes) {
		app.routes = app.routes[:len(app.routes)-4]
		app.effective = previous
		return apiFailure(generated.ErrorCodeIntegrityFailure, "endpoint-registry")
	}
	return nil
}

func (app *Application) restorePlan(config RestoreConfig) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const op = "api.v1.restores.plan"
		var input generated.RestoreRequest
		if err := decodeOperationRequest(r, config.MaxBodyBytes, []string{"schema", "schemaVersion", "expectedStateRevision", "recoveryEpoch", "targetDigest", "idempotencyKey", "source", "fences", "auditDecision", "pointId", "dependencyIds", "targetIds", "priorInstanceId", "newInstanceId", "priorRecoveryEpoch", "nextRecoveryEpoch", "fenceSetDigest", "auditDecisionDigest", "candidateDigest"}, &input); err != nil {
			app.failure(w, op, err)
			return
		}
		principal, ok := identity.PrincipalFromContext(r.Context())
		if !ok {
			app.failure(w, op, apiFailure(generated.ErrorCodeAuthenticationRequired, "principal"))
			return
		}
		if _, err := app.authorizeAction(r, authorization.ActionAuthor, authorization.Target{Capability: "recovery.restore.author", ResourceKind: "recovery-point", ResourceID: input.PointID}); err != nil {
			app.failure(w, op, err)
			return
		}
		requestID, err := config.Results.RequestID()
		if err != nil {
			app.failure(w, op, err)
			return
		}
		value, err := config.Operations.Plan(r.Context(), input, principal)
		if err != nil {
			app.operationFailure(w, op, requestID, err)
			return
		}
		app.operationSuccess(w, op, requestID, true, input.ExpectedStateRevision, input.RecoveryEpoch, value)
	}
}

func (app *Application) restoreRun(config RestoreConfig) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, params map[string]string) {
		const op = "api.v1.restores.run"
		var input generated.RestoreRunRequest
		if !pathToken.MatchString(params["planId"]) {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "path"))
			return
		}
		if err := decodeOperationRequest(r, config.MaxBodyBytes, []string{"schema", "schemaVersion", "expectedStateRevision", "recoveryEpoch", "targetDigest", "idempotencyKey", "source", "pointId", "planId", "planDigest", "humanAcknowledgementId", "fenceSetDigest", "auditDecisionDigest", "candidateDigest", "priorInstanceId", "newInstanceId", "priorRecoveryEpoch", "nextRecoveryEpoch"}, &input); err != nil {
			app.failure(w, op, err)
			return
		}
		if input.PlanID != params["planId"] {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "authorization-target"))
			return
		}
		principal, ok := identity.PrincipalFromContext(r.Context())
		if !ok {
			app.failure(w, op, apiFailure(generated.ErrorCodeAuthenticationRequired, "principal"))
			return
		}
		plan, err := config.Operations.AuthorizationPlan(r.Context(), input.PlanID)
		if err != nil || plan.PlanID != input.PlanID || plan.PlanDigest != input.PlanDigest || len(plan.Operations) != 1 {
			app.failure(w, op, apiFailure(generated.ErrorCodePlanStale, "restore-plan"))
			return
		}
		operation := plan.Operations[0]
		if _, err := app.authorizePlanActionWithoutExpected(r, authorization.ActionExecute, authorization.Target{Capability: operation.OperationType, ResourceKind: "execution-target", ResourceID: operation.TargetID}, plan, []authorization.Branch{authorization.BranchHuman}); err != nil {
			app.failure(w, op, err)
			return
		}
		requestID, err := config.Results.RequestID()
		if err != nil {
			app.failure(w, op, err)
			return
		}
		value, err := config.Operations.Run(r.Context(), input, principal)
		if err != nil {
			app.operationFailure(w, op, requestID, err)
			return
		}
		app.operationSuccess(w, op, requestID, true, input.ExpectedStateRevision, input.RecoveryEpoch, value)
	}
}

func (app *Application) restoreVerify(config RestoreConfig) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, params map[string]string) {
		const op = "api.v1.restores.verify"
		var input generated.RestoreVerifyRequest
		if !pathToken.MatchString(params["planId"]) {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "path"))
			return
		}
		if err := decodeOperationRequest(r, config.MaxBodyBytes, []string{"schema", "schemaVersion", "expectedStateRevision", "recoveryEpoch", "targetDigest", "idempotencyKey", "source", "pointId", "planId", "planDigest", "priorInstanceId", "newInstanceId", "priorRecoveryEpoch", "nextRecoveryEpoch", "fenceSetDigest", "auditDecisionDigest", "candidateDigest"}, &input); err != nil {
			app.failure(w, op, err)
			return
		}
		if input.PlanID != params["planId"] {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "authorization-target"))
			return
		}
		principal, ok := identity.PrincipalFromContext(r.Context())
		if !ok {
			app.failure(w, op, apiFailure(generated.ErrorCodeAuthenticationRequired, "principal"))
			return
		}
		plan, err := config.Operations.AuthorizationPlan(r.Context(), input.PlanID)
		if err != nil || plan.PlanID != input.PlanID || plan.PlanDigest != input.PlanDigest || len(plan.Operations) != 1 {
			app.failure(w, op, apiFailure(generated.ErrorCodePlanStale, "restore-plan"))
			return
		}
		operation := plan.Operations[0]
		if _, err := app.authorizeRecoveryContinuation(r, authorization.Target{Capability: operation.OperationType, ResourceKind: "execution-target", ResourceID: operation.TargetID}, plan, authorization.RevisionBinding{StateRevision: input.ExpectedStateRevision, RecoveryEpoch: input.RecoveryEpoch}); err != nil {
			app.failure(w, op, err)
			return
		}
		requestID, err := config.Results.RequestID()
		if err != nil {
			app.failure(w, op, err)
			return
		}
		value, err := config.Operations.Verify(r.Context(), input, principal)
		if err != nil {
			app.operationFailure(w, op, requestID, err)
			return
		}
		app.operationSuccess(w, op, requestID, true, input.ExpectedStateRevision, input.RecoveryEpoch, value)
	}
}

func (app *Application) restoreGet(config RestoreConfig) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, params map[string]string) {
		const op = "api.v1.restores.get"
		if !pathToken.MatchString(params["planId"]) || r.URL.RawQuery != "" {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "path"))
			return
		}
		value, err := config.Operations.Get(r.Context(), params["planId"])
		if err != nil {
			app.failure(w, op, err)
			return
		}
		app.success(w, op, 0, value.RecoveryEpoch, value)
	}
}
