package api

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"net/http"
)

type OperationsMonitoring struct {
	Readiness func(context.Context, generated.NotificationReadinessRequest) (generated.DeclarationRevision, error)
	Status    func(context.Context) (generated.OperationsStatusData, error)
	Observe   func(context.Context) (generated.OperationsStatusData, error)
}

func RegisterOperationsMonitoring(app *Application, c OperationsMonitoring) error {
	if app == nil || c.Status == nil || c.Observe == nil {
		return apiFailure(generated.ErrorCodeInputInvalid, "operations-config")
	}
	before := len(app.routes)
	app.routes = append(app.routes, route{id: "api.v1.operations.status", method: http.MethodGet, pattern: "/api/v1/operations", capability: "operations.read", kind: "operations-view", handler: app.operationsMonitoringHandler(c, false)}, route{id: "api.v1.operations.observe", method: http.MethodPost, pattern: "/api/v1/operations/observe", capability: "operations.observe", kind: "operations-view", handler: app.operationsMonitoringHandler(c, true)})
	if c.Readiness != nil {
		app.routes = append(app.routes, route{id: "api.v1.operations.notification-readiness", method: http.MethodPost, pattern: "/api/v1/operations/notification-readiness", deferredAuthorization: true, handler: app.notificationReadinessHandler(c)})
	}
	if !routesAreGeneratedSubset(app.routes) {
		app.routes = app.routes[:before]
		return apiFailure(generated.ErrorCodeIntegrityFailure, "endpoint-registry")
	}
	return nil
}
func (app *Application) operationsMonitoringHandler(c OperationsMonitoring, observe bool) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		op := "api.v1.operations.status"
		if observe {
			op = "api.v1.operations.observe"
		}
		if r.URL.RawQuery != "" {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "operations-query"))
			return
		}
		if observe {
			var q generated.OperationsObserveRequest
			if e := decodeOperationRequest(r, 4096, []string{"schema", "schemaVersion"}, &q); e != nil {
				app.failure(w, op, e)
				return
			}
			raw, _ := json.Marshal(q)
			if generated.ValidateContractJSON(generated.SchemaIDOperationsObserveRequest, raw, generated.ContractExact) != nil {
				app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "operations-request"))
				return
			}
		}
		fn := c.Status
		if observe {
			fn = c.Observe
		}
		data, e := fn(r.Context())
		if e != nil {
			app.failure(w, op, e)
			return
		}
		raw, _ := json.Marshal(data)
		if generated.ValidateContractJSON(generated.SchemaIDOperationsStatusData, raw, generated.ContractExact) != nil {
			app.failure(w, op, apiFailure(generated.ErrorCodeIntegrityFailure, "operations-data"))
			return
		}
		app.success(w, op, data.StateRevision, data.RecoveryEpoch, data)
	}
}
