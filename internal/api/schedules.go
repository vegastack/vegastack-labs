package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/schedule"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type ScheduledPolicyStore interface {
	StageDraft(context.Context, generated.ScheduledJobPolicy, audit.Attribution) (store.ScheduledPolicyDraft, error)
	GetActivePolicy(context.Context, string) (generated.ScheduledJobPolicy, error)
}

type ScheduledDispatcher interface {
	Dispatch(context.Context, schedule.DispatchRequest) (generated.ScheduledJob, error)
}

type ScheduledRunner interface {
	Run(context.Context, generated.ScheduledJob, audit.Attribution) (generated.ScheduledJob, error)
}

type ScheduleOperations struct {
	Policies          ScheduledPolicyStore
	Dispatch          ScheduledDispatcher
	Runner            ScheduledRunner
	Results           *result.Factory
	Lifecycle         RunLifecycle
	RunnerPrincipalID string
}

type combinedRunLifecycle struct{ first, second RunLifecycle }

func (l combinedRunLifecycle) Startup(ctx context.Context) error {
	if l.first != nil {
		if err := l.first.Startup(ctx); err != nil {
			return err
		}
	}
	return l.second.Startup(ctx)
}

func RegisterScheduleOperations(app *Application, config ScheduleOperations) error {
	if app == nil || config.Policies == nil || config.Dispatch == nil || config.Runner == nil || config.Results == nil || config.Results != app.config.Results {
		return apiFailure(generated.ErrorCodeInputInvalid, "schedule-config")
	}
	if config.Lifecycle != nil {
		app.runs = combinedRunLifecycle{first: app.runs, second: config.Lifecycle}
	}
	app.routes = append(app.routes,
		route{id: "api.v1.scheduled-job-policies.drafts.create", method: http.MethodPost, pattern: "/api/v1/scheduled-job-policies/drafts", capability: "schedule.policy.author", kind: "scheduled-policy", action: authorization.ActionAuthor, handler: app.scheduledPolicyDraft(config)},
		route{id: "api.v1.scheduled-job-policies.get", method: http.MethodGet, pattern: "/api/v1/scheduled-job-policies/{policyId}", capability: "schedule.policy.read", kind: "scheduled-policy", handler: app.scheduledPolicyGet(config)},
		route{id: "api.v1.scheduled-jobs.create", method: http.MethodPost, pattern: "/api/v1/scheduled-jobs", capability: "schedule.dispatch", kind: "scheduled-job", action: authorization.ActionExecute, handler: app.scheduledDispatch(config)},
	)
	if !routesAreGeneratedSubset(app.routes) {
		app.routes = app.routes[:len(app.routes)-3]
		if combined, ok := app.runs.(combinedRunLifecycle); ok {
			app.runs = combined.first
		}
		return apiFailure(generated.ErrorCodeIntegrityFailure, "endpoint-registry")
	}
	return nil
}

func (app *Application) scheduledPolicyDraft(config ScheduleOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const op = "api.v1.scheduled-job-policies.drafts.create"
		var policy generated.ScheduledJobPolicy
		if err := decodeOperationRequest(r, 65536, []string{"schema", "schemaVersion", "policyId", "revision", "declarationId", "declarationRevision", "approvalPlanId", "approvalPlanDigest", "approvedByHumanId", "actionKind", "operationType", "adapterId", "exactSourceIds", "exactSubjectIds", "exactTargetIds", "maximumWork", "credentialReferenceIds", "grantRevision", "stateRevision", "recoveryEpoch", "policyVersion", "retentionRuleDigest", "anchorAt", "intervalSeconds", "windowSeconds", "catchUp", "concurrency", "maxAttempts", "initialBackoffSeconds", "maximumBackoffSeconds", "expiresAt", "enabled"}, &policy); err != nil {
			app.failure(w, op, err)
			return
		}
		raw, _ := json.Marshal(policy)
		if generated.ValidateContractJSON(generated.SchemaIDScheduledJobPolicy, raw, generated.ContractExact) != nil {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "scheduled-policy-contract"))
			return
		}
		requestID, err := config.Results.RequestID()
		if err != nil {
			app.failure(w, op, err)
			return
		}
		attribution, _, err := gateAuthor(r, requestID)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		draft, err := config.Policies.StageDraft(r.Context(), policy, attribution)
		if err != nil {
			app.operationFailure(w, op, requestID, err)
			return
		}
		submission := generated.ScheduledPolicyDraftSubmission{Schema: generated.SchemaIDScheduledPolicyDraftSubmission, SchemaVersion: "1.1.0", DraftID: draft.DraftID, PolicyID: policy.PolicyID, PolicyRevision: policy.Revision, PolicyDigest: draft.Digest, Status: "draft", StateRevision: policy.StateRevision, RecoveryEpoch: policy.RecoveryEpoch}
		app.operationSuccess(w, op, requestID, true, policy.StateRevision, policy.RecoveryEpoch, submission)
	}
}

func (app *Application) scheduledPolicyGet(config ScheduleOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, params map[string]string) {
		const op = "api.v1.scheduled-job-policies.get"
		policyID := params["policyId"]
		if !pathToken.MatchString(policyID) || r.URL.RawQuery != "" {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "path"))
			return
		}
		policy, err := config.Policies.GetActivePolicy(r.Context(), policyID)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		app.success(w, op, policy.StateRevision, policy.RecoveryEpoch, policy)
	}
}

func (app *Application) scheduledDispatch(config ScheduleOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const op = "api.v1.scheduled-jobs.create"
		principal, authenticated := identity.PrincipalFromContext(r.Context())
		if config.RunnerPrincipalID != "" && (!authenticated || principal.ID != config.RunnerPrincipalID) {
			app.failure(w, op, apiFailure(generated.ErrorCodeAuthorizationDenied, "scheduled-runner-principal"))
			return
		}
		var input generated.ScheduledJobRequest
		if err := decodeOperationRequest(r, 65536, []string{"schema", "schemaVersion", "expectedStateRevision", "recoveryEpoch", "targetDigest", "idempotencyKey", "policyId", "policyRevision", "occurrenceToken", "observedAt"}, &input); err != nil {
			app.failure(w, op, err)
			return
		}
		raw, _ := json.Marshal(input)
		request, err := schedule.DecodeRequest(raw)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		requestID, err := config.Results.RequestID()
		if err != nil {
			app.failure(w, op, err)
			return
		}
		attribution, _, err := gateAuthor(r, requestID)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		job, err := config.Dispatch.Dispatch(r.Context(), request)
		if err == nil && (job.Status == "queued" || job.Status == "retry-wait") {
			job, err = config.Runner.Run(r.Context(), job, attribution)
		}
		if err != nil {
			app.operationFailure(w, op, input.IdempotencyKey, err)
			return
		}
		app.operationSuccess(w, op, input.IdempotencyKey, true, input.ExpectedStateRevision, input.RecoveryEpoch, job)
	}
}
