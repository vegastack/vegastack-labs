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
)

// BackupPolicyDraftService stores one inert canonical backup-policy draft. The
// concrete store repository satisfies this directly; the interface keeps the
// handler testable and free of a SQLite dependency.
type BackupPolicyDraftService interface {
	CreateBackupPolicyDraft(context.Context, generated.BackupPolicyDraftRequest, audit.Attribution) (generated.BackupPolicyDraftSubmission, error)
}

type BackupStatusService interface {
	ReadLocalBackupStatus(context.Context) (generated.BackupStatusData, error)
	ReadLocalBackupStatusScoped(context.Context, authorization.ReadScope) (generated.BackupStatusData, error)
}

// BackupOperations exposes the backup catalog and submits exact backup plans
// through the same run executor used by the generic plan route.
type BackupOperations struct {
	Drafts             BackupPolicyDraftService
	RetentionLocks     RetentionLockDraftService
	Retirements        RetirementDraftService
	OffsiteRetirements OffsiteRetirementStageService
	Status             BackupStatusService
	Runs               RunOperationConfig
	Results            *result.Factory
}

func RegisterBackupOperations(app *Application, config BackupOperations) error {
	if app == nil || config.Drafts == nil || config.Results == nil || config.Results != app.config.Results {
		return apiFailure(generated.ErrorCodeInputInvalid, "backup-config")
	}
	app.routes = append(app.routes, route{id: "api.v1.backup-policy-drafts.create", method: http.MethodPost, pattern: "/api/v1/backups/policies/drafts", capability: "backup.policy.author", kind: "backup-policy", action: authorization.ActionAuthor, handler: app.backupPolicyDraft(config)})
	added := 1
	if config.Retirements != nil {
		app.routes = append(app.routes, route{id: "api.v1.backup-retirement-drafts.create", method: http.MethodPost, pattern: "/api/v1/backups/retirements/drafts", deferredAuthorization: true, handler: app.backupRetirementDraft(config)})
		added++
	}
	if config.OffsiteRetirements != nil {
		app.routes = append(app.routes, route{id: "api.v1.backup-offsite-retirements.stage", method: http.MethodPost, pattern: "/api/v1/backups/offsite-retirements/stage", deferredAuthorization: true, handler: app.backupOffsiteRetirementStage(config)})
		added++
	}
	if config.RetentionLocks != nil {
		app.routes = append(app.routes, route{id: "api.v1.backup-retention-lock-drafts.create", method: http.MethodPost, pattern: "/api/v1/backups/retention-locks/drafts", deferredAuthorization: true, handler: app.backupRetentionLockDraft(config)})
		added++
	}
	if config.Status != nil && config.Runs.Runs != nil && config.Runs.Plans != nil && config.Runs.Acknowledgements != nil && config.Runs.Results == config.Results {
		app.routes = append(app.routes,
			route{id: "api.v1.backups.status", method: http.MethodGet, pattern: "/api/v1/backups/status", capability: "backup.read", kind: "backup", handler: app.backupStatus(config)},
			route{id: "api.v1.backups.run", method: http.MethodPost, pattern: "/api/v1/backups/run", deferredAuthorization: true, handler: app.backupRun(config)},
			route{id: "api.v1.backups.verify", method: http.MethodPost, pattern: "/api/v1/backups/{jobId}/verify", deferredAuthorization: true, handler: app.backupVerify(config)},
		)
		added += 3
	}
	if !routesAreGeneratedSubset(app.routes) {
		app.routes = app.routes[:len(app.routes)-added]
		return apiFailure(generated.ErrorCodeIntegrityFailure, "endpoint-registry")
	}
	return nil
}

func (app *Application) backupOffsiteRetirementStage(config BackupOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const op = "api.v1.backup-offsite-retirements.stage"
		if r.URL.RawQuery != "" {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "query"))
			return
		}
		var input generated.BackupOffsiteRetirementStageRequest
		if err := decodeOperationRequest(r, 65536, []string{"schema", "schemaVersion", "expectedStateRevision", "recoveryEpoch", "targetDigest", "idempotencyKey", "selectionDigest", "planId", "planDigest", "oneOwnerProofId", "lockAdminConsumerId", "retentionConsumerId"}, &input); err != nil {
			app.failure(w, op, err)
			return
		}
		principal, ok := identity.PrincipalFromContext(r.Context())
		if !ok || principal.Method != identity.LocalOSPeerMethod {
			app.failure(w, op, apiFailure(generated.ErrorCodeAuthorizationDenied, "offsite-retirement-operator-only"))
			return
		}
		requestID, err := config.Results.RequestID()
		if err != nil {
			app.failure(w, op, err)
			return
		}
		result, err := config.OffsiteRetirements.Stage(r.Context(), input, principal)
		if err != nil {
			app.operationFailure(w, op, requestID, err)
			return
		}
		app.operationSuccess(w, op, requestID, true, result.StateRevision, result.RecoveryEpoch, result)
	}
}

func (app *Application) backupStatus(config BackupOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, scope authorization.ReadScope, _ map[string]string) {
		const op = "api.v1.backups.status"
		if r.URL.RawQuery != "" {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "query"))
			return
		}
		status, err := config.Status.ReadLocalBackupStatusScoped(r.Context(), scope)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		app.success(w, op, 0, status.RecoveryEpoch, status)
	}
}

func (app *Application) backupRun(config BackupOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const op = "api.v1.backups.run"
		var input generated.BackupRunRequest
		app.backupExecute(w, r, config, op, "backup.local.create", "", &input)
	}
}

func (app *Application) backupVerify(config BackupOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, params map[string]string) {
		const op = "api.v1.backups.verify"
		if !pathToken.MatchString(params["jobId"]) {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "job"))
			return
		}
		var input generated.BackupVerifyRequest
		app.backupExecute(w, r, config, op, "backup.local.verify", params["jobId"], &input)
	}
}

func (app *Application) backupExecute(w http.ResponseWriter, r *http.Request, config BackupOperations, op, operationType, pathJobID string, destination any) {
	// A route carries only an exact plan reference and target checks. The plan
	// executor remains the sole authorization, acknowledgement and run path.
	if r.URL.RawQuery != "" {
		app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "query"))
		return
	}
	var planID, planDigest, ackID, key, targetDigest, targetID, pointID string
	var epoch, revision int64
	switch input := destination.(type) {
	case *generated.BackupRunRequest:
		if err := decodeOperationRequest(r, 4096, []string{"schema", "schemaVersion", "expectedStateRevision", "recoveryEpoch", "targetDigest", "idempotencyKey", "policyId", "policyRevision", "planId", "planDigest", "humanAcknowledgementId"}, input); err != nil {
			app.failure(w, op, err)
			return
		}
		raw, _ := json.Marshal(input)
		if generated.ValidateContractJSON(generated.SchemaIDBackupRunRequest, raw, generated.ContractExact) != nil {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "backup-run-contract"))
			return
		}
		planID, planDigest, ackID, key, targetDigest, targetID, epoch, revision = input.PlanID, input.PlanDigest, input.HumanAcknowledgementID, input.IdempotencyKey, input.TargetDigest, input.PolicyID, input.RecoveryEpoch, input.ExpectedStateRevision
	case *generated.BackupVerifyRequest:
		if err := decodeOperationRequest(r, 4096, []string{"schema", "schemaVersion", "expectedStateRevision", "recoveryEpoch", "targetDigest", "idempotencyKey", "jobId", "pointId", "planId", "planDigest", "humanAcknowledgementId"}, input); err != nil {
			app.failure(w, op, err)
			return
		}
		raw, _ := json.Marshal(input)
		if generated.ValidateContractJSON(generated.SchemaIDBackupVerifyRequest, raw, generated.ContractExact) != nil || input.JobID != pathJobID {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "backup-verify-contract"))
			return
		}
		planID, planDigest, ackID, key, targetDigest, targetID, pointID, epoch, revision = input.PlanID, input.PlanDigest, input.HumanAcknowledgementID, input.IdempotencyKey, input.TargetDigest, input.PointID, input.PointID, input.RecoveryEpoch, input.ExpectedStateRevision
	default:
		app.failure(w, op, apiFailure(generated.ErrorCodeIntegrityFailure, "backup-request"))
		return
	}
	stored, err := config.Runs.Plans.GetPlan(r.Context(), planID)
	if err != nil {
		app.failure(w, op, err)
		return
	}
	plan := stored.Plan
	if plan.PlanDigest != planDigest || plan.Binding.StateRevision != revision || plan.Binding.RecoveryEpoch != epoch || len(plan.Operations) != 1 || plan.Operations[0].OperationType != operationType || plan.Operations[0].AdapterID != "local.backup" || plan.Operations[0].TargetID != targetID || plan.Operations[0].InputDigest != targetDigest {
		app.failure(w, op, apiFailure(generated.ErrorCodePlanStale, "backup-plan"))
		return
	}
	decision, err := app.authorizeRunPlan(r, plan)
	if err != nil {
		app.failure(w, op, err)
		return
	}
	if pointID != "" {
		status, err := config.Status.ReadLocalBackupStatus(r.Context())
		if err != nil {
			app.failure(w, op, err)
			return
		}
		found := false
		for _, job := range status.Jobs {
			if job.JobID == pathJobID && job.PointID != nil && *job.PointID == pointID && job.RecoveryEpoch == epoch && job.Status == "pending" {
				found = true
				break
			}
		}
		if !found {
			app.failure(w, op, apiFailure(generated.ErrorCodePrerequisiteBlocked, "backup-pending-point"))
			return
		}
	}
	reference := generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: planID, PlanDigest: planDigest, RecoveryEpoch: epoch, IdempotencyKey: key, Extensions: []generated.ContractExtension{}}
	run, err := app.submitExactPlan(r, config.Runs, plan, decision, reference, ackID)
	if err != nil && run.RunID == "" {
		app.operationFailure(w, op, key, err)
		return
	}
	if err != nil || run.Status != generated.RunStatusSucceeded {
		app.operationFailure(w, op, key, apiFailure(generated.ErrorCodeRecoveryRequired, "backup-run"))
		return
	}
	status, statusErr := config.Status.ReadLocalBackupStatus(r.Context())
	if statusErr != nil {
		app.operationFailure(w, op, key, statusErr)
		return
	}
	for _, job := range status.Jobs {
		if (pathJobID != "" && job.JobID == pathJobID) || (pathJobID == "" && job.RunID != nil && *job.RunID == run.RunID) {
			app.operationSuccess(w, op, key, true, run.StateRevision, run.RecoveryEpoch, job)
			return
		}
	}
	app.operationFailure(w, op, key, apiFailure(generated.ErrorCodeRecoveryRequired, "backup-job-unresolved"))
}

func (app *Application) backupPolicyDraft(config BackupOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const op = "api.v1.backup-policy-drafts.create"
		var input generated.BackupPolicyDraftRequest
		if err := decodeOperationRequest(r, 65536, []string{"schema", "schemaVersion", "expectedStateRevision", "recoveryEpoch", "targetDigest", "idempotencyKey", "policy"}, &input); err != nil {
			app.failure(w, op, err)
			return
		}
		raw, _ := json.Marshal(input)
		if generated.ValidateContractJSON(generated.SchemaIDBackupPolicyDraftRequest, raw, generated.ContractExact) != nil {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "backup-policy-contract"))
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
		submission, err := config.Drafts.CreateBackupPolicyDraft(r.Context(), input, attribution)
		if err != nil {
			app.operationFailure(w, op, requestID, err)
			return
		}
		app.operationSuccess(w, op, requestID, true, submission.StateRevision, submission.RecoveryEpoch, submission)
	}
}
