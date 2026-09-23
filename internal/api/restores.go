package api

import (
	"context"
	"net/http"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/result"
)

// RestoreOperations is the already-authorized orchestration boundary. The
// implementation binds the authenticated principal to the immutable plan and
// acknowledgement before it changes recovery state.
type RestoreOperations interface {
	Plan(context.Context, generated.RestoreRequest) (generated.RestoreBinding, error)
	Run(context.Context, generated.RestoreRunRequest) (generated.RestoreBinding, error)
	Verify(context.Context, generated.RestoreVerifyRequest) (generated.RestoreVerification, error)
	Get(context.Context, string) (generated.BrowserRestoreStatus, error)
}

type RestoreConfig struct {
	Operations   RestoreOperations
	Results      *result.Factory
	MaxBodyBytes int64
}

func RegisterRestoreOperations(app *Application, config RestoreConfig) error {
	if app == nil || config.Operations == nil || config.Results == nil || config.Results != app.config.Results {
		return apiFailure(generated.ErrorCodeInputInvalid, "restore-config")
	}
	if config.MaxBodyBytes == 0 {
		config.MaxBodyBytes = MaxOperationRequestBytes
	}
	if config.MaxBodyBytes < 1 || config.MaxBodyBytes > MaxOperationRequestBytes {
		return apiFailure(generated.ErrorCodeInputInvalid, "restore-limit")
	}
	app.routes = append(app.routes,
		route{id: "api.v1.restores.get", method: http.MethodGet, pattern: "/api/v1/restores/plans/{planId}", capability: "restore.read", kind: "restore-plan", handler: app.restoreGet(config)},
		route{id: "api.v1.restores.plan", method: http.MethodPost, pattern: "/api/v1/restores/plans", deferredAuthorization: true, handler: app.restorePlan(config)},
		route{id: "api.v1.restores.run", method: http.MethodPost, pattern: "/api/v1/restores/plans/{planId}/run", deferredAuthorization: true, handler: app.restoreRun(config)},
		route{id: "api.v1.restores.verify", method: http.MethodPost, pattern: "/api/v1/restores/plans/{planId}/verify", deferredAuthorization: true, handler: app.restoreVerify(config)},
	)
	if !routesAreGeneratedSubset(app.routes) {
		app.routes = app.routes[:len(app.routes)-4]
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
		requestID, err := config.Results.RequestID()
		if err != nil {
			app.failure(w, op, err)
			return
		}
		value, err := config.Operations.Plan(r.Context(), input)
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
		requestID, err := config.Results.RequestID()
		if err != nil {
			app.failure(w, op, err)
			return
		}
		value, err := config.Operations.Run(r.Context(), input)
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
		if err := decodeOperationRequest(r, config.MaxBodyBytes, []string{"schema", "schemaVersion", "expectedStateRevision", "recoveryEpoch", "targetDigest", "idempotencyKey", "source", "pointId", "planId", "planDigest", "priorInstanceId", "newInstanceId", "priorRecoveryEpoch", "nextRecoveryEpoch", "fenceSetDigest", "auditDecisionDigest", "candidateDigest", "canaryDigest"}, &input); err != nil {
			app.failure(w, op, err)
			return
		}
		if input.PlanID != params["planId"] {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "authorization-target"))
			return
		}
		requestID, err := config.Results.RequestID()
		if err != nil {
			app.failure(w, op, err)
			return
		}
		value, err := config.Operations.Verify(r.Context(), input)
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
