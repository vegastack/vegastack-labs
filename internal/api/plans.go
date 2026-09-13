package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	planengine "github.com/vegastack/vegastack-labs/internal/plan"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type PlanService interface {
	Prepare(context.Context, string, int64) (generated.PlanPreparation, error)
	Create(context.Context, planengine.AuthorScope, generated.PlanCreateRequest) (store.PlanCommitResult, error)
	Get(context.Context, string) (store.PlanCommitResult, error)
}

type DeclarationPlanConfig struct {
	Declarations  DeclarationService
	Plans         PlanService
	Results       *result.Factory
	Authorization EffectiveAuthorizationConfig
	MaxBodyBytes  int64
}

func RegisterDeclarationPlanOperations(app *Application, config DeclarationPlanConfig) error {
	if app == nil || config.Declarations == nil || config.Plans == nil || config.Results == nil || config.Results != app.config.Results || config.Authorization.Authorizer == nil || config.Authorization.Recorder == nil {
		return apiFailure(generated.ErrorCodeInputInvalid, "declaration-plan-config")
	}
	if config.Authorization.Clock == nil {
		config.Authorization.Clock = time.Now
	}
	if config.MaxBodyBytes == 0 {
		config.MaxBodyBytes = MaxOperationRequestBytes
	}
	if config.MaxBodyBytes < 1 || config.MaxBodyBytes > MaxOperationRequestBytes {
		return apiFailure(generated.ErrorCodeInputInvalid, "declaration-plan-limit")
	}
	previous := app.effective
	app.effective = config.Authorization
	app.routes = append(app.routes,
		route{id: "api.v1.declarations.revise", method: http.MethodPost, pattern: "/api/v1/declarations/{declarationId}/revisions", capability: "declaration.author", kind: "declaration", action: authorization.ActionAuthor, handler: app.reviseDeclaration(config)},
		route{id: "api.v1.declarations.get", method: http.MethodGet, pattern: "/api/v1/declarations/{declarationId}/revisions/{revision}", capability: "declaration.read", kind: "declaration", handler: app.getDeclaration(config)},
		route{id: "api.v1.declarations.plan-preparation.get", method: http.MethodGet, pattern: "/api/v1/declarations/{declarationId}/revisions/{revision}/plan-preparation", capability: "declaration.read", kind: "declaration", handler: app.preparePlan(config)},
		route{id: "api.v1.plans.create", method: http.MethodPost, pattern: "/api/v1/declarations/{declarationId}/plans", capability: "plan.author", kind: "declaration", action: authorization.ActionAuthor, handler: app.createPlan(config)},
		route{id: "api.v1.plans.get", method: http.MethodGet, pattern: "/api/v1/plans/{planId}", capability: "plan.read", kind: "plan", handler: app.getPlan(config)},
	)
	if !routesAreGeneratedSubset(app.routes) {
		app.routes = app.routes[:len(app.routes)-5]
		app.effective = previous
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

func (app *Application) preparePlan(config DeclarationPlanConfig) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(writer http.ResponseWriter, request *http.Request, _ authorization.ReadScope, params map[string]string) {
		const operation = "api.v1.declarations.plan-preparation.get"
		revision, err := strconv.ParseInt(params["revision"], 10, 64)
		if !pathToken.MatchString(params["declarationId"]) || err != nil || revision < 1 || strconv.FormatInt(revision, 10) != params["revision"] || request.URL.RawQuery != "" {
			app.failure(writer, operation, apiFailure(generated.ErrorCodeInputInvalid, "path"))
			return
		}
		preparation, err := config.Plans.Prepare(request.Context(), params["declarationId"], revision)
		if err != nil {
			app.failure(writer, operation, err)
			return
		}
		raw, err := json.Marshal(preparation)
		if err != nil || preparation.DeclarationID != params["declarationId"] || preparation.DeclarationRevision != revision || generated.ValidateContractJSON(generated.SchemaIDPlanPreparation, raw, generated.ContractExact) != nil {
			app.failure(writer, operation, apiFailure(generated.ErrorCodeIntegrityFailure, "plan-preparation"))
			return
		}
		app.success(writer, operation, preparation.ExpectedStateRevision, preparation.RecoveryEpoch, preparation)
	}
}

func (app *Application) createPlan(config DeclarationPlanConfig) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(writer http.ResponseWriter, request *http.Request, _ authorization.ReadScope, params map[string]string) {
		const operation = "api.v1.plans.create"
		var input generated.PlanCreateRequest
		if err := decodeOperationRequest(request, config.MaxBodyBytes, []string{"schema", "schemaVersion", "declarationId", "declarationRevision", "expectedStateRevision", "recoveryEpoch", "observationFingerprint", "idempotencyKey", "extensions"}, &input); err != nil {
			app.failure(writer, operation, err)
			return
		}
		if input.DeclarationID != params["declarationId"] {
			app.failure(writer, operation, apiFailure(generated.ErrorCodeInputInvalid, "authorization-target"))
			return
		}
		principal, ok := identity.PrincipalFromContext(request.Context())
		if !ok {
			app.failure(writer, operation, apiFailure(generated.ErrorCodeAuthenticationRequired, "principal"))
			return
		}
		if _, err := app.authorizeAction(request, authorization.ActionAuthor, authorization.Target{Capability: "plan.author", ResourceKind: "declaration", ResourceID: input.DeclarationID}); err != nil {
			app.failure(writer, operation, err)
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
		presentation, err := presentPlan(value)
		if err != nil {
			app.operationFailure(writer, operation, requestID, err)
			return
		}
		app.operationSuccess(writer, operation, requestID, value.Commit.Changed, value.Commit.StateRevision, value.Commit.RecoveryEpoch, presentation)
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
		presentation, err := presentPlan(value)
		if err != nil {
			app.failure(writer, operation, err)
			return
		}
		app.success(writer, operation, value.Plan.Binding.StateRevision, value.Plan.Binding.RecoveryEpoch, presentation)
	}
}

func presentPlan(value store.PlanCommitResult) (generated.PlanPresentation, error) {
	if len(value.Canonical) == 0 || value.Readable == "" {
		return generated.PlanPresentation{}, apiFailure(generated.ErrorCodeIntegrityFailure, "plan-presentation")
	}
	var exact generated.Plan
	canonical, err := json.Marshal(value.Plan)
	decodeErr := json.Unmarshal(value.Canonical, &exact)
	if err != nil || decodeErr != nil || !bytes.Equal(canonical, value.Canonical) || exact.PlanID != value.Plan.PlanID || exact.PlanDigest != value.Plan.PlanDigest {
		return generated.PlanPresentation{}, apiFailure(generated.ErrorCodeIntegrityFailure, "plan-presentation")
	}
	return generated.PlanPresentation{Plan: value.Plan, ReadablePlan: value.Readable, CanonicalPlan: string(value.Canonical)}, nil
}
