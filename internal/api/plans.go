package api

import (
	"context"
	"net/http"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	planengine "github.com/vegastack/vegastack-labs/internal/plan"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type PlanService interface {
	Create(context.Context, planengine.AuthorScope, generated.PlanCreateRequest) (store.PlanCommitResult, error)
	Get(context.Context, string) (store.PlanCommitResult, error)
}

type DeclarationPlanConfig struct {
	Declarations DeclarationService
	Plans        PlanService
	Results      *result.Factory
	MaxBodyBytes int64
}

func RegisterDeclarationPlanOperations(app *Application, config DeclarationPlanConfig) error {
	if app == nil || config.Declarations == nil || config.Plans == nil || config.Results == nil || config.Results != app.config.Results {
		return apiFailure(generated.ErrorCodeInputInvalid, "declaration-plan-config")
	}
	if config.MaxBodyBytes == 0 {
		config.MaxBodyBytes = MaxOperationRequestBytes
	}
	if config.MaxBodyBytes < 1 || config.MaxBodyBytes > MaxOperationRequestBytes {
		return apiFailure(generated.ErrorCodeInputInvalid, "declaration-plan-limit")
	}
	app.routes = append(app.routes,
		route{"api.v1.declarations.revise", http.MethodPost, "/api/v1/declarations", "declaration.revise", "declaration", app.reviseDeclaration(config)},
		route{"api.v1.declarations.get", http.MethodGet, "/api/v1/declarations/{declarationId}/revisions/{revision}", "declaration.read", "declaration", app.getDeclaration(config)},
		route{"api.v1.plans.create", http.MethodPost, "/api/v1/plans", "plan.create", "plan", app.createPlan(config)},
		route{"api.v1.plans.get", http.MethodGet, "/api/v1/plans/{planId}", "plan.read", "plan", app.getPlan(config)},
	)
	if !routesAreGeneratedSubset(app.routes) {
		app.routes = app.routes[:len(app.routes)-4]
		return apiFailure(generated.ErrorCodeIntegrityFailure, "endpoint-registry")
	}
	return nil
}

func ValidateRegisteredRoutes(app *Application) error {
	if app == nil || !routesMatchGenerated(app.routes) {
		return apiFailure(generated.ErrorCodeIntegrityFailure, "endpoint-registry")
	}
	return nil
}

func (app *Application) createPlan(config DeclarationPlanConfig) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(writer http.ResponseWriter, request *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const operation = "api.v1.plans.create"
		var input generated.PlanCreateRequest
		if err := decodeOperationRequest(request, config.MaxBodyBytes, []string{"schema", "schemaVersion", "declarationId", "declarationRevision", "expectedStateRevision", "recoveryEpoch", "observationFingerprint", "idempotencyKey", "extensions"}, &input); err != nil {
			app.failure(writer, operation, err)
			return
		}
		principal, ok := identity.PrincipalFromContext(request.Context())
		if !ok {
			app.failure(writer, operation, apiFailure(generated.ErrorCodeAuthenticationRequired, "principal"))
			return
		}
		requestID, err := config.Results.RequestID()
		if err != nil {
			app.failure(writer, operation, err)
			return
		}
		value, err := config.Plans.Create(request.Context(), planengine.AuthorScope{PrincipalID: principal.ID, PrincipalMethod: principal.Method, AgentSessionID: requestID}, input)
		if err != nil {
			app.operationFailure(writer, operation, requestID, err)
			return
		}
		app.operationSuccess(writer, operation, requestID, value.Commit.Changed, value.Commit.StateRevision, value.Commit.RecoveryEpoch, value.Plan)
	}
}

func (app *Application) getPlan(config DeclarationPlanConfig) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(writer http.ResponseWriter, request *http.Request, _ authorization.ReadScope, params map[string]string) {
		const operation = "api.v1.plans.get"
		if !pathToken.MatchString(params["planId"]) || request.URL.RawQuery != "" {
			app.failure(writer, operation, apiFailure(generated.ErrorCodeInputInvalid, "path"))
			return
		}
		value, err := config.Plans.Get(request.Context(), params["planId"])
		if err != nil {
			app.failure(writer, operation, err)
			return
		}
		app.success(writer, operation, value.Plan.Binding.StateRevision, value.Plan.Binding.RecoveryEpoch, value.Plan)
	}
}
