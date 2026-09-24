package api

import (
	"context"
	"net/http"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/result"
)

type DatabaseExportService interface {
	Draft(context.Context, generated.DatabaseExportRequest, change.AuthorScope) (generated.DatabaseExportDraftSubmission, bool, error)
}

type DatabaseOperations struct {
	Backups  BackupOperations
	Restores RestoreConfig
	Exports  DatabaseExportService
	Results  *result.Factory
}

// RegisterDatabaseOperations exposes database-specific aliases over the same
// server-owned backup and restore effects. Every route authorizes the fixed
// database resource before decoding its body. Export only records an inert
// declaration and never creates or publishes an artifact.
func RegisterDatabaseOperations(app *Application, config DatabaseOperations) error {
	if app == nil || config.Results == nil || config.Results != app.config.Results || config.Exports == nil || config.Backups.Runs.Runs == nil || config.Backups.Runs.Plans == nil || config.Backups.Runs.Acknowledgements == nil || config.Restores.Operations == nil {
		return apiFailure(generated.ErrorCodeInputInvalid, "database-operations-config")
	}
	if config.Restores.MaxBodyBytes == 0 {
		config.Restores.MaxBodyBytes = MaxOperationRequestBytes
	}
	app.routes = append(app.routes,
		route{id: "api.v1.database-backups.create", method: http.MethodPost, pattern: "/api/v1/database/backups", capability: "backup.execute", kind: "database", action: authorization.ActionAuthor, staticResourceID: "database", handler: app.databaseBackup(config)},
		route{id: "api.v1.database-verifications.create", method: http.MethodPost, pattern: "/api/v1/database/verifications", capability: "backup.verify", kind: "database", action: authorization.ActionAuthor, staticResourceID: "database", handler: app.databaseVerify(config)},
		route{id: "api.v1.database-restores.create", method: http.MethodPost, pattern: "/api/v1/database/restores", capability: "recovery.restore.author", kind: "database", action: authorization.ActionAuthor, staticResourceID: "database", handler: app.databaseRestore(config)},
		route{id: "api.v1.database-exports.create", method: http.MethodPost, pattern: "/api/v1/database/exports", capability: "database.export.author", kind: "database", action: authorization.ActionAuthor, staticResourceID: "database", handler: app.databaseExport(config)},
	)
	if !routesAreGeneratedSubset(app.routes) {
		app.routes = app.routes[:len(app.routes)-4]
		return apiFailure(generated.ErrorCodeIntegrityFailure, "endpoint-registry")
	}
	return nil
}

func (app *Application) databaseBackup(config DatabaseOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		var input generated.BackupRunRequest
		app.backupExecute(w, r, config.Backups, "api.v1.database-backups.create", "backup.local.create", "", &input)
	}
}

func (app *Application) databaseVerify(config DatabaseOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		var input generated.BackupVerifyRequest
		app.backupExecute(w, r, config.Backups, "api.v1.database-verifications.create", "backup.local.verify", "", &input)
	}
}

func (app *Application) databaseRestore(config DatabaseOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const op = "api.v1.database-restores.create"
		var input generated.RestoreRequest
		if err := decodeOperationRequest(r, config.Restores.MaxBodyBytes, []string{"schema", "schemaVersion", "expectedStateRevision", "recoveryEpoch", "targetDigest", "idempotencyKey", "source", "fences", "auditDecision", "pointId", "dependencyIds", "targetIds", "priorInstanceId", "newInstanceId", "priorRecoveryEpoch", "nextRecoveryEpoch", "fenceSetDigest", "auditDecisionDigest", "candidateDigest", "formerHostId", "replacementHostId", "recoveryDraftId", "ciphertextFingerprint", "sourceAdmissionDigest", "fenceQualificationDigest", "recoveryRunId", "recoveryStepId", "recoveryLeaseId", "recoveryChallengeId", "recoveryReceiptId", "canaryRunId", "canaryStepId", "canaryLeaseId", "canaryChallengeId", "canaryReceiptId", "canaryBindingDigest"}, &input); err != nil {
			app.failure(w, op, err)
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
		value, err := config.Restores.Operations.Plan(r.Context(), input, principal)
		if err != nil {
			app.operationFailure(w, op, requestID, err)
			return
		}
		app.operationSuccess(w, op, requestID, true, input.ExpectedStateRevision, input.RecoveryEpoch, value)
	}
}

func (app *Application) databaseExport(config DatabaseOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const op = "api.v1.database-exports.create"
		var input generated.DatabaseExportRequest
		if err := decodeOperationRequest(r, 4096, []string{"schema", "schemaVersion", "expectedStateRevision", "recoveryEpoch", "targetDigest", "idempotencyKey", "exportId", "kind"}, &input); err != nil {
			app.failure(w, op, err)
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
		value, changed, err := config.Exports.Draft(r.Context(), input, change.AuthorScope{PrincipalID: principal.ID, PrincipalMethod: principal.Method, AgentSessionID: requestID})
		if err != nil {
			app.operationFailure(w, op, requestID, err)
			return
		}
		app.operationSuccess(w, op, requestID, changed, value.StateRevision, value.RecoveryEpoch, value)
	}
}
