package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/result"
)

// BackupPolicyDraftService stores one inert canonical backup-policy draft. The
// concrete store repository satisfies this directly; the interface keeps the
// handler testable and free of a SQLite dependency.
type BackupPolicyDraftService interface {
	CreateBackupPolicyDraft(context.Context, generated.BackupPolicyDraftRequest, audit.Attribution) (generated.BackupPolicyDraftSubmission, error)
}

// BackupOperations only drafts inert canonical policy bytes. It deliberately has
// no route that runs, verifies, or activates a backup; those remain planned for
// #117 and execute solely through the existing declaration/plan/run flow.
type BackupOperations struct {
	Drafts  BackupPolicyDraftService
	Results *result.Factory
}

func RegisterBackupOperations(app *Application, config BackupOperations) error {
	if app == nil || config.Drafts == nil || config.Results == nil || config.Results != app.config.Results {
		return apiFailure(generated.ErrorCodeInputInvalid, "backup-config")
	}
	app.routes = append(app.routes, route{id: "api.v1.backup-policy-drafts.create", method: http.MethodPost, pattern: "/api/v1/backups/policies/drafts", capability: "backup.policy.author", kind: "backup-policy", action: authorization.ActionAuthor, handler: app.backupPolicyDraft(config)})
	if !routesAreGeneratedSubset(app.routes) {
		app.routes = app.routes[:len(app.routes)-1]
		return apiFailure(generated.ErrorCodeIntegrityFailure, "endpoint-registry")
	}
	return nil
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
