package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// RestoreOperations is the already-authorized orchestration boundary. The
// implementation binds the authenticated principal to the immutable plan and
// acknowledgement before it changes recovery state.
type RestoreOperations interface {
	Plan(context.Context, generated.RestoreRequest, identity.Principal) (generated.RestoreBinding, error)
	Run(context.Context, generated.RestoreRunRequest, identity.Principal) (generated.RestoreBinding, error)
	Verify(context.Context, generated.RestoreVerifyRequest, identity.Principal) (generated.RestoreVerification, error)
	Get(context.Context, string) (generated.BrowserRestoreStatus, error)
	List(context.Context, authorization.ReadScope, store.RevisionToken, string, int) ([]generated.BrowserRestoreStatus, store.RevisionToken, error)
	AuthorizationPlan(context.Context, string) (generated.Plan, error)
}

type RestoreConfig struct {
	Operations    RestoreOperations
	Declarations  DeclarationService
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
		route{id: "api.v1.restores.list", method: http.MethodGet, pattern: "/api/v1/restore-plans", capability: "restore.read", kind: "restore-plan", handler: app.restoreList(config)},
		route{id: "api.v1.restores.plan", method: http.MethodPost, pattern: "/api/v1/recovery-points/{pointId}/restore-plans", capability: "recovery.restore.author", kind: "recovery-point", action: authorization.ActionAuthor, resourceParam: "pointId", handler: app.restorePlan(config)},
		route{id: "api.v1.restores.run", method: http.MethodPost, pattern: "/api/v1/restore-plans/{planId}/runs", capability: "recovery.restore.cutover", kind: "restore-plan", action: authorization.ActionAuthor, resourceParam: "planId", handler: app.restoreRun(config)},
		route{id: "api.v1.restores.verify", method: http.MethodPost, pattern: "/api/v1/restore-plans/{planId}/verifications", capability: "recovery.restore.cutover", kind: "restore-plan", action: authorization.ActionAuthor, resourceParam: "planId", handler: app.restoreVerify(config)},
	)
	if config.Declarations != nil {
		app.routes = append(app.routes, route{id: "api.v1.restore-drafts.create", method: http.MethodPost, pattern: "/api/v1/recovery-points/{pointId}/restore-drafts", capability: "recovery.restore.author", kind: "recovery-point", action: authorization.ActionAuthor, resourceParam: "pointId", handler: app.restoreDraft(config)})
	}
	added := 4
	if config.Declarations != nil {
		added++
	}
	if !routesAreGeneratedSubset(app.routes) {
		app.routes = app.routes[:len(app.routes)-added]
		app.effective = previous
		return apiFailure(generated.ErrorCodeIntegrityFailure, "endpoint-registry")
	}
	return nil
}

func (app *Application) restorePlan(config RestoreConfig) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, params map[string]string) {
		const op = "api.v1.restores.plan"
		var input generated.RestoreRequest
		if err := decodeOperationRequest(r, config.MaxBodyBytes, []string{"schema", "schemaVersion", "expectedStateRevision", "recoveryEpoch", "targetDigest", "idempotencyKey", "source", "fences", "auditDecision", "pointId", "dependencyIds", "targetIds", "priorInstanceId", "newInstanceId", "priorRecoveryEpoch", "nextRecoveryEpoch", "fenceSetDigest", "auditDecisionDigest", "candidateDigest", "formerHostId", "replacementHostId", "recoveryDraftId", "ciphertextFingerprint", "sourceAdmissionDigest", "fenceQualificationDigest", "recoveryRunId", "recoveryStepId", "recoveryLeaseId", "recoveryChallengeId", "recoveryReceiptId", "canaryRunId", "canaryStepId", "canaryLeaseId", "canaryChallengeId", "canaryReceiptId", "canaryBindingDigest"}, &input); err != nil {
			app.failure(w, op, err)
			return
		}
		if input.PointID != params["pointId"] {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "restore-point-path"))
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
		if err := decodeOperationRequest(r, config.MaxBodyBytes, []string{"schema", "schemaVersion", "expectedStateRevision", "recoveryEpoch", "targetDigest", "idempotencyKey", "source", "pointId", "planId", "planDigest", "humanAcknowledgementId", "fenceSetDigest", "auditDecisionDigest", "candidateDigest", "priorInstanceId", "newInstanceId", "priorRecoveryEpoch", "nextRecoveryEpoch", "recoveryRunId", "recoveryStepId", "recoveryLeaseId", "recoveryChallengeId", "recoveryReceiptId", "canaryRunId", "canaryStepId", "canaryLeaseId", "canaryChallengeId", "canaryReceiptId", "canaryBindingDigest"}, &input); err != nil {
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
		if err != nil || plan.PlanID != input.PlanID || plan.PlanDigest != input.PlanDigest || len(plan.Operations) != 2 {
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
		if err != nil || plan.PlanID != input.PlanID || plan.PlanDigest != input.PlanDigest || len(plan.Operations) != 2 {
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

func (app *Application) restoreList(config RestoreConfig) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, scope authorization.ReadScope, _ map[string]string) {
		const op = "api.v1.restores.list"
		page, err := app.phase5PageRequest(r, scope, op)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		items, revision, err := config.Operations.List(r.Context(), scope, page.Snapshot, page.AfterID, page.Query.Limit+1)
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
			lastID = items[len(items)-1].PlanID
		}
		next, err := app.phase5NextCursor(op, scope, page, lastID, hasMore)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		app.success(w, op, revision.StateRevision, revision.RecoveryEpoch, generated.BrowserRestoreStatusListData{Schema: generated.SchemaIDBrowserRestoreStatusListData, SchemaVersion: "1.0.0", Items: items, NextCursor: next, StateRevision: revision.StateRevision, RecoveryEpoch: revision.RecoveryEpoch})
	}
}

func (app *Application) restoreDraft(config RestoreConfig) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, params map[string]string) {
		const op = "api.v1.restore-drafts.create"
		var input generated.BrowserRestoreDraftRequest
		if err := decodeOperationRequest(r, 4096, []string{"schema", "schemaVersion", "expectedStateRevision", "recoveryEpoch", "targetDigest", "idempotencyKey", "pointId"}, &input); err != nil || input.PointID != params["pointId"] {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "restore-draft"))
			return
		}
		principal, ok := identity.PrincipalFromContext(r.Context())
		if !ok {
			app.failure(w, op, apiFailure(generated.ErrorCodeAuthenticationRequired, "principal"))
			return
		}
		requestID, err := config.Results.RequestID()
		if err != nil {
			app.failure(w, op, err)
			return
		}
		digestSuffix := strings.TrimPrefix(input.TargetDigest, "sha256:")
		if len(digestSuffix) < 32 {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "restore-draft-digest"))
			return
		}
		declarationID := "restore-draft-" + digestSuffix[:32]
		request := generated.DeclarationRevisionRequest{Schema: generated.SchemaIDDeclarationRevisionRequest, SchemaVersion: "1.0.0", DeclarationID: declarationID, DeclarationType: "recovery.restore-intent", ExpectedRevision: 1, ExpectedStateRevision: input.ExpectedStateRevision, RecoveryEpoch: input.RecoveryEpoch, Operations: []generated.DeclarationOperation{{Sequence: 1, OperationID: "prepare-restore", OperationType: "recovery.restore.prepare", AdapterID: "core.recovery", TargetID: input.PointID, InputDigest: input.TargetDigest, ArtifactDigest: input.TargetDigest, Idempotent: true}}, ReasonDigest: input.TargetDigest, Extensions: []generated.ContractExtension{}}
		value, err := config.Declarations.Revise(r.Context(), change.AuthorScope{PrincipalID: principal.ID, PrincipalMethod: principal.Method, AgentSessionID: requestID}, request)
		if err != nil {
			app.operationFailure(w, op, requestID, err)
			return
		}
		data := generated.BrowserRestoreDraftSubmission{Schema: generated.SchemaIDBrowserRestoreDraftSubmission, SchemaVersion: "1.0.0", DraftID: value.Document.DeclarationID, ChangeID: value.Document.ContentDigest, PointID: input.PointID, Status: "draft", StateRevision: value.Document.StateRevision, RecoveryEpoch: value.Document.RecoveryEpoch}
		app.operationSuccess(w, op, requestID, value.Changed, data.StateRevision, data.RecoveryEpoch, data)
	}
}
