package api

import (
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"net/http"
)

func (app *Application) notificationReadinessHandler(c OperationsMonitoring) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const op = "api.v1.operations.notification-readiness"
		if _, e := app.authorizeAction(r, authorization.ActionAuthor, authorization.Target{Capability: "operations.notification-readiness.prepare", ResourceKind: "notification-routes", ResourceID: "scope"}); e != nil {
			app.failure(w, op, e)
			return
		}
		var q generated.NotificationReadinessRequest
		if e := decodeOperationRequest(r, 8192, []string{"schema", "schemaVersion", "action", "requestId", "expectedStateRevision", "recoveryEpoch"}, &q, "runId"); e != nil {
			app.failure(w, op, e)
			return
		}
		raw, _ := json.Marshal(q)
		if r.URL.RawQuery != "" || generated.ValidateContractJSON(generated.SchemaIDNotificationReadinessRequest, raw, generated.ContractExact) != nil {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "notification-readiness-request"))
			return
		}
		requestID, idErr := app.config.Results.RequestID()
		if idErr != nil {
			app.failure(w, op, idErr)
			return
		}
		d, e := c.Readiness(r.Context(), q)
		if e != nil {
			app.failure(w, op, e)
			return
		}
		app.operationSuccess(w, op, requestID, true, d.StateRevision, d.RecoveryEpoch, d)
	}
}
