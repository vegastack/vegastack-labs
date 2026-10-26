package api

import (
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
	"net/http"
	"net/url"
	"strconv"
)

func RegisterOperatorAccessOperations(app *Application, repo *store.OperatorAccessRepository) error {
	if app == nil || repo == nil {
		return apiFailure(generated.ErrorCodeInputInvalid, "operator-access-config")
	}
	n := len(app.routes)
	for _, kind := range []string{"people", "devices", "grants"} {
		app.routes = append(app.routes, route{id: "api.v1." + kind + ".list", method: http.MethodGet, pattern: "/api/v1/" + kind, deferredAuthorization: true, handler: app.operatorRead(repo, kind)})
	}
	if !routesAreGeneratedSubset(app.routes) {
		app.routes = app.routes[:n]
		return apiFailure(generated.ErrorCodeIntegrityFailure, "endpoint-registry")
	}
	return nil
}
func (app *Application) operatorRead(repo *store.OperatorAccessRepository, kind string) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		op := "api.v1." + kind + ".list"
		q, err := operatorReadQuery(r, kind)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		switch kind {
		case "people":
			v, e := repo.ListPeople(r.Context(), q.After, int(q.Limit))
			if e != nil {
				app.failure(w, op, e)
				return
			}
			app.success(w, op, v.StateRevision, v.RecoveryEpoch, v)
		case "devices":
			v, e := repo.ListDevices(r.Context(), q.PrincipalID, q.After, int(q.Limit))
			if e != nil {
				app.failure(w, op, e)
				return
			}
			app.success(w, op, v.StateRevision, v.RecoveryEpoch, v)
		case "grants":
			v, e := repo.ListGrants(r.Context(), q.PrincipalID, q.After, int(q.Limit))
			if e != nil {
				app.failure(w, op, e)
				return
			}
			app.success(w, op, v.StateRevision, v.RecoveryEpoch, v)
		}
	}
}
func operatorReadQuery(r *http.Request, kind string) (generated.OperatorReadQuery, error) {
	q := generated.OperatorReadQuery{Limit: 100}
	v, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return q, apiFailure(generated.ErrorCodeInputInvalid, "operator-query")
	}
	for k, values := range v {
		if len(values) != 1 || values[0] == "" {
			err = apiFailure(generated.ErrorCodeInputInvalid, "operator-query")
			break
		}
		switch k {
		case "after":
			q.After = values[0]
		case "principalId":
			if kind == "people" {
				err = apiFailure(generated.ErrorCodeInputInvalid, "operator-query")
			}
			q.PrincipalID = values[0]
		case "limit":
			var n int
			n, err = strconv.Atoi(values[0])
			q.Limit = int64(n)
		default:
			err = apiFailure(generated.ErrorCodeInputInvalid, "operator-query")
		}
		if err != nil {
			break
		}
	}
	if err != nil || q.Limit < 1 || q.Limit > 100 || kind != "people" && q.PrincipalID == "" {
		return q, apiFailure(generated.ErrorCodeInputInvalid, "operator-query")
	}
	return q, nil
}

// ProviderConfiguration is a finite sanitized composition summary. Configuration
// proves neither reachability nor qualification of the selected adapters.
type ProviderConfiguration struct{ Identity, Acknowledgement, LocalBackup, OffsiteBackup bool }

func RegisterProviderReadOperations(app *Application, repo *store.OperatorAccessRepository, c ProviderConfiguration) error {
	if app == nil || repo == nil {
		return apiFailure(generated.ErrorCodeInputInvalid, "provider-read-config")
	}
	app.routes = append(app.routes, route{id: "api.v1.providers.list", method: http.MethodGet, pattern: "/api/v1/providers", capability: "platform.source.read", kind: "platform-source", staticResourceID: "providers", handler: func(w http.ResponseWriter, r *http.Request, scope authorization.ReadScope, _ map[string]string) {
		const op = "api.v1.providers.list"
		if r.URL.RawQuery != "" {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "provider-query"))
			return
		}
		rev, err := repo.ProviderRevision(r.Context(), scope)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		v := generated.OperatorProviderList{Schema: generated.SchemaIDOperatorProviderList, SchemaVersion: "1.0.0", StateRevision: rev.StateRevision, RecoveryEpoch: rev.RecoveryEpoch, Providers: []generated.OperatorProvider{}}
		for _, entry := range []struct {
			id         string
			configured bool
		}{{"identity", c.Identity}, {"acknowledgement", c.Acknowledgement}, {"backup.local", c.LocalBackup}, {"backup.offsite", c.OffsiteBackup}} {
			state := "unavailable"
			if entry.configured {
				state = "unknown"
			}
			v.Providers = append(v.Providers, generated.OperatorProvider{Schema: generated.SchemaIDOperatorProvider, SchemaVersion: "1.0.0", Capability: entry.id, Configured: entry.configured, Connectivity: state})
		}
		app.success(w, op, v.StateRevision, v.RecoveryEpoch, v)
	}})
	if !routesAreGeneratedSubset(app.routes) {
		app.routes = app.routes[:len(app.routes)-1]
		return apiFailure(generated.ErrorCodeIntegrityFailure, "endpoint-registry")
	}
	return nil
}
