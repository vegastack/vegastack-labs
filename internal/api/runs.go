package api

import (
	"context"
	"net/http"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/result"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type RunService interface {
	Submit(context.Context, runengine.SubmitRequest) (generated.Run, error)
	Get(context.Context, string) (generated.Run, error)
	CancelAs(context.Context, string, audit.Attribution) (generated.Run, error)
	ResumeAs(context.Context, string, audit.Attribution) (generated.Run, error)
}

type RunPlanSource interface {
	GetPlan(context.Context, string) (store.PlanCommitResult, error)
}

type RunAcknowledgementSource interface {
	ForPlan(context.Context, generated.Plan) (*generated.Acknowledgement, error)
}

type RunOperationConfig struct {
	Runs             RunService
	Plans            RunPlanSource
	Acknowledgements RunAcknowledgementSource
	Results          *result.Factory
	Authorization    EffectiveAuthorizationConfig
	MaxBodyBytes     int64
}

func RegisterRunOperations(app *Application, config RunOperationConfig) error {
	if app == nil || config.Runs == nil || config.Plans == nil || config.Results == nil || config.Results != app.config.Results || config.Authorization.Authorizer == nil || config.Authorization.Recorder == nil {
		return apiFailure(generated.ErrorCodeInputInvalid, "run-operation-config")
	}
	if config.Authorization.Clock == nil {
		config.Authorization.Clock = time.Now
	}
	if config.MaxBodyBytes == 0 {
		config.MaxBodyBytes = MaxOperationRequestBytes
	}
	if config.MaxBodyBytes < 1 || config.MaxBodyBytes > MaxOperationRequestBytes {
		return apiFailure(generated.ErrorCodeInputInvalid, "run-operation-limit")
	}
	previous := app.effective
	app.effective = config.Authorization
	app.routes = append(app.routes,
		route{id: "api.v1.plans.execute", method: http.MethodPost, pattern: "/api/v1/plans/{planId}/execute", deferredAuthorization: true, handler: app.executePlan(config)},
		route{id: "api.v1.runs.get", method: http.MethodGet, pattern: "/api/v1/runs/{runId}", capability: "run.read", kind: "run", handler: app.getRun(config)},
		route{id: "api.v1.runs.cancel", method: http.MethodPost, pattern: "/api/v1/runs/{runId}/cancel", deferredAuthorization: true, handler: app.mutateRun(config, false)},
		route{id: "api.v1.runs.resume", method: http.MethodPost, pattern: "/api/v1/runs/{runId}/resume", deferredAuthorization: true, handler: app.mutateRun(config, true)},
	)
	if !routesAreGeneratedSubset(app.routes) {
		app.routes = app.routes[:len(app.routes)-4]
		app.effective = previous
		return apiFailure(generated.ErrorCodeIntegrityFailure, "endpoint-registry")
	}
	return nil
}

func (app *Application) executePlan(config RunOperationConfig) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, request *http.Request, _ authorization.ReadScope, params map[string]string) {
		const operation = "api.v1.plans.execute"
		planID := params["planId"]
		if !pathToken.MatchString(planID) || request.URL.RawQuery != "" {
			app.failure(w, operation, apiFailure(generated.ErrorCodeInputInvalid, "path"))
			return
		}
		stored, err := config.Plans.GetPlan(request.Context(), planID)
		if err != nil {
			app.failure(w, operation, err)
			return
		}
		decision, err := app.authorizeRunPlan(request, stored.Plan)
		if err != nil {
			app.failure(w, operation, err)
			return
		}
		ack, err := app.runAcknowledgement(request.Context(), config, stored.Plan)
		if err != nil {
			app.failure(w, operation, err)
			return
		}
		var input generated.PlanReferenceRequest
		if err := decodeOperationRequest(request, config.MaxBodyBytes, []string{"schema", "schemaVersion", "planId", "planDigest", "recoveryEpoch", "idempotencyKey", "extensions"}, &input); err != nil {
			app.failure(w, operation, err)
			return
		}
		if input.PlanID != planID || input.PlanDigest != stored.Plan.PlanDigest {
			app.failure(w, operation, apiFailure(generated.ErrorCodePlanStale, "plan"))
			return
		}
		if input.RecoveryEpoch != stored.Plan.Binding.RecoveryEpoch {
			app.failure(w, operation, apiFailure(generated.ErrorCodeRecoveryEpochMismatch, "plan"))
			return
		}
		attribution, err := runAttribution(request, ack, config.Results)
		if err != nil {
			app.failure(w, operation, err)
			return
		}
		value, err := config.Runs.Submit(request.Context(), runengine.SubmitRequest{Reference: input, Authorization: decision, Acknowledgement: ack, Attribution: attribution})
		if err != nil {
			app.operationFailure(w, operation, decision.DecisionID, err)
			return
		}
		app.operationSuccess(w, operation, decision.DecisionID, value.Changed, value.StateRevision, value.RecoveryEpoch, value)
	}
}

func (app *Application) getRun(config RunOperationConfig) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, request *http.Request, _ authorization.ReadScope, params map[string]string) {
		const operation = "api.v1.runs.get"
		id := params["runId"]
		if !pathToken.MatchString(id) || request.URL.RawQuery != "" {
			app.failure(w, operation, apiFailure(generated.ErrorCodeInputInvalid, "path"))
			return
		}
		value, err := config.Runs.Get(request.Context(), id)
		if err != nil {
			app.failure(w, operation, err)
			return
		}
		app.success(w, operation, value.StateRevision, value.RecoveryEpoch, value)
	}
}

func (app *Application) mutateRun(config RunOperationConfig, resume bool) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, request *http.Request, _ authorization.ReadScope, params map[string]string) {
		operation := "api.v1.runs.cancel"
		if resume {
			operation = "api.v1.runs.resume"
		}
		id := params["runId"]
		if !pathToken.MatchString(id) || request.URL.RawQuery != "" {
			app.failure(w, operation, apiFailure(generated.ErrorCodeInputInvalid, "path"))
			return
		}
		current, err := config.Runs.Get(request.Context(), id)
		if err != nil {
			app.failure(w, operation, err)
			return
		}
		stored, err := config.Plans.GetPlan(request.Context(), current.PlanID)
		if err != nil {
			app.failure(w, operation, err)
			return
		}
		_, err = app.authorizeRunPlan(request, stored.Plan)
		if err != nil {
			app.failure(w, operation, err)
			return
		}
		var input generated.RunReferenceRequest
		if err := decodeOperationRequest(request, config.MaxBodyBytes, []string{"schema", "schemaVersion", "runId", "idempotencyKey", "recoveryEpoch", "extensions"}, &input); err != nil {
			app.failure(w, operation, err)
			return
		}
		if input.RunID != id {
			app.failure(w, operation, apiFailure(generated.ErrorCodeInputInvalid, "run"))
			return
		}
		if input.RecoveryEpoch != current.RecoveryEpoch || current.RecoveryEpoch != stored.Plan.Binding.RecoveryEpoch {
			app.failure(w, operation, apiFailure(generated.ErrorCodeRecoveryEpochMismatch, "run"))
			return
		}
		ack, err := app.runAcknowledgement(request.Context(), config, stored.Plan)
		if err != nil {
			app.failure(w, operation, err)
			return
		}
		attribution, err := runAttribution(request, ack, config.Results)
		if err != nil {
			app.failure(w, operation, err)
			return
		}
		var value generated.Run
		if resume {
			value, err = config.Runs.ResumeAs(request.Context(), id, attribution)
		} else {
			value, err = config.Runs.CancelAs(request.Context(), id, attribution)
		}
		if err != nil {
			app.operationFailure(w, operation, input.IdempotencyKey, err)
			return
		}
		app.operationSuccess(w, operation, input.IdempotencyKey, value.Changed, value.StateRevision, value.RecoveryEpoch, value)
	}
}

func (app *Application) authorizeRunPlan(request *http.Request, plan generated.Plan) (generated.AuthorizationDecision, error) {
	if len(plan.Operations) == 0 {
		return generated.AuthorizationDecision{}, apiFailure(generated.ErrorCodeInputInvalid, "plan-operations")
	}
	var result generated.AuthorizationDecision
	seen := map[string]bool{}
	for _, operation := range plan.Operations {
		key := operation.OperationType + "\x00" + operation.TargetID
		if seen[key] {
			continue
		}
		seen[key] = true
		outcome, err := app.authorize(request, authorization.Request{Action: authorization.ActionExecute, Target: authorization.Target{Capability: operation.OperationType, ResourceKind: "execution-target", ResourceID: operation.TargetID}, Plan: &plan, Branches: []authorization.Branch{authorization.Branch(plan.AuthorizationBranch)}})
		if err != nil {
			return generated.AuthorizationDecision{}, err
		}
		decision, err := projectAuthorizationDecision(outcome.Record)
		if err != nil {
			return generated.AuthorizationDecision{}, err
		}
		if result.DecisionID == "" {
			result = decision
		}
	}
	return result, nil
}

func (app *Application) runAcknowledgement(ctx context.Context, config RunOperationConfig, plan generated.Plan) (*generated.Acknowledgement, error) {
	if plan.AuthorizationBranch == string(authorization.BranchPreauthorized) {
		return nil, nil
	}
	if config.Acknowledgements == nil {
		return nil, apiFailure(generated.ErrorCodeApprovalRequired, "acknowledgement")
	}
	return config.Acknowledgements.ForPlan(ctx, plan)
}

func runAttribution(request *http.Request, acknowledgement *generated.Acknowledgement, results *result.Factory) (audit.Attribution, error) {
	principal, ok := identity.PrincipalFromContext(request.Context())
	if !ok {
		return audit.Attribution{}, apiFailure(generated.ErrorCodeAuthenticationRequired, "principal")
	}
	requestID, err := results.RequestID()
	if err != nil {
		return audit.Attribution{}, err
	}
	var responsible *identity.Principal
	var agent *audit.AgentMetadata
	switch identity.EffectivePrincipalKind(principal) {
	case identity.PrincipalHuman:
		responsible = &principal
	case identity.PrincipalAgent:
		if acknowledgement == nil {
			return audit.Attribution{}, apiFailure(generated.ErrorCodeApprovalRequired, "responsible-human")
		}
		responsible = &identity.Principal{ID: acknowledgement.HumanID, Kind: identity.PrincipalHuman, Method: identity.LocalOSPeerMethod}
		agent = &audit.AgentMetadata{Name: principal.ID, SessionID: requestID}
	}
	attribution, err := audit.NewAttribution(principal, responsible, agent)
	if err != nil {
		return audit.Attribution{}, apiFailure(generated.ErrorCodeIntegrityFailure, "run-attribution")
	}
	return attribution, nil
}
