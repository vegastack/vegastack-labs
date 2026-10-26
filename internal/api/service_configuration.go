package api

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/principal"
	"net/http"
)

type ServiceConfigurationOperations struct {
	Configuration func(context.Context, string) (generated.ServiceConfigurationStatus, error)
}

func RegisterServiceConfigurationOperations(app *Application, c ServiceConfigurationOperations) error {
	if app == nil || c.Configuration == nil {
		return apiFailure(generated.ErrorCodeInputInvalid, "service-configuration")
	}
	before := len(app.routes)
	app.routes = append(app.routes, route{id: "api.v1.services.configuration.get", method: http.MethodGet, pattern: "/api/v1/services/{serviceID}/configuration", deferredAuthorization: true, handler: func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, params map[string]string) {
		const op = "api.v1.services.configuration.get"
		id := params["serviceID"]
		if r.URL.RawQuery != "" || !principal.ValidID(id) {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "service-query"))
			return
		}
		scope, e := app.authorizeAction(r, authorization.ActionRead, authorization.Target{Capability: "service.read", ResourceKind: "service", ResourceID: id})
		if e != nil {
			app.failure(w, op, e)
			return
		}
		data, e := c.Configuration(r.Context(), id)
		if e != nil {
			app.failure(w, op, e)
			return
		}
		if data.ServiceID != id {
			app.failure(w, op, apiFailure(generated.ErrorCodeIntegrityFailure, "service-configuration"))
			return
		}
		app.success(w, op, scope.StateRevision, scope.RecoveryEpoch, data)
	}})
	if !routesAreGeneratedSubset(app.routes) {
		app.routes = app.routes[:before]
		return apiFailure(generated.ErrorCodeIntegrityFailure, "endpoint-registry")
	}
	return nil
}
