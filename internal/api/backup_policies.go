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
	"github.com/vegastack/vegastack-labs/internal/store"
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
	CurrentBackupRevision(context.Context, authorization.ReadScope) (store.RevisionToken, error)
	ListRecoveryPoints(context.Context, authorization.ReadScope, string, int) ([]generated.BrowserRecoveryPoint, store.RevisionToken, error)
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
	app.routes = append(app.routes, route{id: "api.v1.backup-policy-drafts.create", method: http.MethodPost, pattern: "/api/v1/backups/policies/drafts", capability: "backup.policy.author", kind: "backup-policy", action: authorization.ActionAuthor, staticResourceID: "policy-drafts", handler: app.backupPolicyDraft(config)})
	added := 1
	if config.Retirements != nil {
		app.routes = append(app.routes, route{id: "api.v1.backup-retirement-drafts.create", method: http.MethodPost, pattern: "/api/v1/backups/retirements/drafts", deferredAuthorization: true, handler: app.backupRetirementDraft(config)})
		added++
	}
	if config.OffsiteRetirements != nil {
		app.routes = append(app.routes,
			route{id: "api.v1.backup-offsite-retirements.dry-run", method: http.MethodPost, pattern: "/api/v1/backups/offsite-retirements/dry-run", deferredAuthorization: true, handler: app.backupOffsiteRetirementDryRun(config)},
			route{id: "api.v1.backup-offsite-retirements.stage", method: http.MethodPost, pattern: "/api/v1/backups/offsite-retirements/stage", deferredAuthorization: true, handler: app.backupOffsiteRetirementStage(config)},
		)
		added += 2
	}
	if config.RetentionLocks != nil {
		app.routes = append(app.routes, route{id: "api.v1.backup-retention-lock-drafts.create", method: http.MethodPost, pattern: "/api/v1/backups/retention-locks/drafts", deferredAuthorization: true, handler: app.backupRetentionLockDraft(config)})
		added++
	}
	if config.Status != nil && config.Runs.Runs != nil && config.Runs.Plans != nil && config.Runs.Acknowledgements != nil && config.Runs.Results == config.Results {
		app.routes = append(app.routes,
			route{id: "api.v1.backups.status", method: http.MethodGet, pattern: "/api/v1/backups/status", capability: "backup.read", kind: "backup", staticResourceID: "current", handler: app.backupStatus(config)},
			route{id: "api.v1.backup-jobs.create", method: http.MethodPost, pattern: "/api/v1/backup-policies/{policyId}/jobs", capability: "backup.execute", kind: "backup-policy", action: authorization.ActionAuthor, resourceParam: "policyId", handler: app.backupRun(config)},
			route{id: "api.v1.backup-verifications.create", method: http.MethodPost, pattern: "/api/v1/recovery-points/{pointId}/verifications", capability: "backup.verify", kind: "recovery-point", action: authorization.ActionAuthor, resourceParam: "pointId", handler: app.backupVerify(config)},
			route{id: "api.v1.recovery-points.list", method: http.MethodGet, pattern: "/api/v1/recovery-points", capability: "backup.read", kind: "recovery-point", staticResourceID: "points", handler: app.recoveryPointList(config)},
		)
		added += 4
	}
	if !routesAreGeneratedSubset(app.routes) {
		app.routes = app.routes[:len(app.routes)-added]
		return apiFailure(generated.ErrorCodeIntegrityFailure, "endpoint-registry")
	}
	return nil
}

func (app *Application) backupOffsiteRetirementDryRun(config BackupOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const op = "api.v1.backup-offsite-retirements.dry-run"
		if r.URL.RawQuery != "" {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "query"))
			return
		}
		var input generated.BackupOffsiteRetirementDryRunRequest
		if err := decodeOperationRequest(r, 65536, []string{"schema", "schemaVersion", "expectedStateRevision", "recoveryEpoch", "selectionDigest", "oneOwnerProofId", "lockAdminReferenceId", "retentionReferenceId"}, &input); err != nil {
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
		result, err := config.OffsiteRetirements.DryRun(r.Context(), input, principal)
		if err != nil {
			app.operationFailure(w, op, requestID, err)
			return
		}
		app.operationSuccess(w, op, requestID, false, result.StateRevision, result.RecoveryEpoch, result)
	}
}

func (app *Application) backupOffsiteRetirementStage(config BackupOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const op = "api.v1.backup-offsite-retirements.stage"
		if r.URL.RawQuery != "" {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "query"))
			return
		}
		var input generated.BackupOffsiteRetirementStageRequest
		if err := decodeOperationRequest(r, 65536, []string{"schema", "schemaVersion", "expectedStateRevision", "recoveryEpoch", "targetDigest", "idempotencyKey", "selectionDigest", "planId", "planDigest", "oneOwnerProofId", "lockAdminReferenceId", "retentionReferenceId", "credentialBindingDigest"}, &input); err != nil {
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
		revision, err := config.Status.CurrentBackupRevision(r.Context(), scope)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		projected := browserBackupStatus(status)
		projected.StateRevision = revision.StateRevision
		raw, marshalErr := json.Marshal(projected)
		if marshalErr != nil || generated.ValidateContractJSON(generated.SchemaIDBrowserBackupStatusData, raw, generated.ContractExact) != nil {
			app.failure(w, op, apiFailure(generated.ErrorCodeIntegrityFailure, "backup-status-projection"))
			return
		}
		app.success(w, op, projected.StateRevision, projected.RecoveryEpoch, projected)
	}
}

func browserBackupStatus(status generated.BackupStatusData) generated.BrowserBackupStatusData {
	result := generated.BrowserBackupStatusData{Schema: generated.SchemaIDBrowserBackupStatusData, SchemaVersion: "1.0.0", Status: "empty", ReasonCode: "no-recovery-point", SourceKind: "none", ProofClass: "none", RecoveryEpoch: status.RecoveryEpoch, SafeNextAction: "create and verify a recovery point"}
	if len(status.LastGood) > 0 {
		result.Status, result.ReasonCode, result.SourceKind, result.ProofClass = "healthy", "verified-recovery-point", "local", "live"
		result.LastGoodPointID = &status.LastGood[0].PointID
		result.SafeNextAction = "none"
		return result
	}
	for _, job := range status.Jobs {
		result.SourceKind, result.ProofClass = job.SourceKind, job.ProofClass
		if job.Status == "failed" {
			result.Status, result.ReasonCode, result.RecoveryRequired, result.SafeNextAction = "failed", "backup-job-failed", true, "inspect the failed backup job"
			return result
		}
		result.Status, result.ReasonCode, result.SafeNextAction = "pending", "verification-pending", "verify the pending recovery point"
	}
	return result
}

func (app *Application) recoveryPointList(config BackupOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, scope authorization.ReadScope, _ map[string]string) {
		const op = "api.v1.recovery-points.list"
		page, err := app.phase5PageRequest(r, scope, op)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		items, revision, err := config.Status.ListRecoveryPoints(r.Context(), scope, page.AfterID, page.Query.Limit+1)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		if revision != page.Snapshot {
			app.failure(w, op, apiFailure(generated.ErrorCodeStateConflict, "cursor"))
			return
		}
		hasMore := len(items) > page.Query.Limit
		if hasMore {
			items = items[:page.Query.Limit]
		}
		var lastID string
		if len(items) > 0 {
			lastID = items[len(items)-1].PointID
		}
		next, err := app.phase5NextCursor(op, scope, page, lastID, hasMore)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		app.success(w, op, revision.StateRevision, revision.RecoveryEpoch, generated.BrowserRecoveryPointListData{Schema: generated.SchemaIDBrowserRecoveryPointListData, SchemaVersion: "1.0.0", Items: items, NextCursor: next, StateRevision: revision.StateRevision, RecoveryEpoch: revision.RecoveryEpoch})
	}
}

func (app *Application) backupRun(config BackupOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, params map[string]string) {
		const op = "api.v1.backup-jobs.create"
		var input generated.BackupRunRequest
		app.backupExecute(w, r, config, op, "backup.local.create", params["policyId"], &input)
	}
}

func (app *Application) backupVerify(config BackupOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, params map[string]string) {
		const op = "api.v1.backup-verifications.create"
		if !pathToken.MatchString(params["pointId"]) {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "point"))
			return
		}
		var input generated.BackupVerifyRequest
		app.backupExecute(w, r, config, op, "backup.local.verify", params["pointId"], &input)
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
		if generated.ValidateContractJSON(generated.SchemaIDBackupRunRequest, raw, generated.ContractExact) != nil || (pathJobID != "" && input.PolicyID != pathJobID) {
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
		if generated.ValidateContractJSON(generated.SchemaIDBackupVerifyRequest, raw, generated.ContractExact) != nil || (pathJobID != "" && input.PointID != pathJobID) {
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
			if job.PointID != nil && *job.PointID == pointID && job.RecoveryEpoch == epoch && job.Status == "pending" {
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
		if (pointID != "" && job.PointID != nil && *job.PointID == pointID) || (pointID == "" && job.RunID != nil && *job.RunID == run.RunID) {
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
