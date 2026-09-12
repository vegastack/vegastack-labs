package api

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/inventory"
	"github.com/vegastack/vegastack-labs/internal/readmodel"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type route struct {
	id, method, pattern, capability, kind string
	handler                               func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string)
}

var pathToken = regexp.MustCompile(`^[a-z][a-z0-9._:-]{0,127}$`)

var remoteSessionEndpoints = map[string]bool{
	"api.v1.session.create": true,
	"api.v1.session.renew":  true,
	"api.v1.session.logout": true,
}

// RemoteReadRequestAllowed is the server-side admission boundary for the
// browser listener. Generated available GET endpoints are readable remotely;
// the three browser-session POST operations are the only write-method
// exceptions. New local operations remain remote-denied until this metadata
// rule deliberately admits them.
func RemoteReadRequestAllowed(method, requestPath string) bool {
	for _, endpoint := range generated.Endpoints {
		if endpoint.Availability != "available" || endpoint.Method != method || (method != http.MethodGet && !remoteSessionEndpoints[endpoint.ID]) {
			continue
		}
		if _, ok := matchPath(endpoint.Path, requestPath); ok {
			return true
		}
	}
	return false
}

func finiteRoutes(app *Application) []route {
	return []route{
		{"api.v1.session.create", http.MethodPost, "/api/v1/session", "", "", app.sessionCreate},
		{"api.v1.session.renew", http.MethodPost, "/api/v1/session/renew", "", "", app.sessionRenew},
		{"api.v1.session.logout", http.MethodPost, "/api/v1/session/logout", "", "", app.sessionLogout},
		{"api.v1.database-status.get", http.MethodGet, "/api/v1/database/status", "database.status.read", "database", app.databaseStatus},
		{"api.v1.summary.get", http.MethodGet, "/api/v1/summary", "platform.summary.read", "platform-summary", app.summary},
		{"api.v1.sources.list", http.MethodGet, "/api/v1/sources", "platform.source.read", "platform-source", app.sourceList},
		{"api.v1.inventory-drafts.list", http.MethodGet, "/api/v1/inventory-drafts", "inventory.draft.read", "inventory-draft", app.draftList},
		{"api.v1.inventory-drafts.get", http.MethodGet, "/api/v1/inventory-drafts/{draftId}/revisions/{revision}", "inventory.draft.read", "inventory-draft", app.draftGet},
		{"api.v1.inventory-draft-assets.list", http.MethodGet, "/api/v1/inventory-drafts/{draftId}/revisions/{revision}/assets", "inventory.draft.read", "inventory-draft", app.recordList("asset")},
		{"api.v1.inventory-draft-assets.get", http.MethodGet, "/api/v1/inventory-drafts/{draftId}/revisions/{revision}/assets/{recordId}", "inventory.draft.read", "inventory-draft", app.recordGet("asset")},
		{"api.v1.inventory-draft-nodes.list", http.MethodGet, "/api/v1/inventory-drafts/{draftId}/revisions/{revision}/nodes", "inventory.draft.read", "inventory-draft", app.recordList("node")},
		{"api.v1.inventory-draft-nodes.get", http.MethodGet, "/api/v1/inventory-drafts/{draftId}/revisions/{revision}/nodes/{recordId}", "inventory.draft.read", "inventory-draft", app.recordGet("node")},
		{"api.v1.inventory-draft-aliases.list", http.MethodGet, "/api/v1/inventory-drafts/{draftId}/revisions/{revision}/aliases", "inventory.draft.read", "inventory-draft", app.recordList("alias")},
		{"api.v1.inventory-draft-aliases.get", http.MethodGet, "/api/v1/inventory-drafts/{draftId}/revisions/{revision}/aliases/{recordId}", "inventory.draft.read", "inventory-draft", app.recordGet("alias")},
		{"api.v1.inventory-draft-observations.list", http.MethodGet, "/api/v1/inventory-drafts/{draftId}/revisions/{revision}/observations", "inventory.draft.read", "inventory-draft", app.recordList("observation")},
		{"api.v1.inventory-draft-observations.get", http.MethodGet, "/api/v1/inventory-drafts/{draftId}/revisions/{revision}/observations/{recordId}", "inventory.draft.read", "inventory-draft", app.recordGet("observation")},
	}
}

type registeredRoute struct{ method, path string }

func implementedRoutes(routes []route) map[string]registeredRoute {
	implemented := map[string]registeredRoute{"api.v1.health.get": {http.MethodGet, "/api/v1/health"}, "api.v1.events.stream": {http.MethodGet, "/api/v1/events"}}
	for _, candidate := range routes {
		implemented[candidate.id] = registeredRoute{candidate.method, candidate.pattern}
	}
	return implemented
}

func routesAreGeneratedSubset(routes []route) bool {
	want := make(map[string]registeredRoute, len(generated.Endpoints))
	for _, endpoint := range generated.Endpoints {
		want[endpoint.ID] = registeredRoute{endpoint.Method, endpoint.Path}
	}
	for id, candidate := range implementedRoutes(routes) {
		if want[id] != candidate {
			return false
		}
	}
	return true
}

func routesMatchGenerated(routes []route) bool {
	implemented := implementedRoutes(routes)
	available := 0
	for _, endpoint := range generated.Endpoints {
		if endpoint.Availability == generated.AvailabilityAvailable {
			available++
		}
	}
	if len(implemented) != available {
		return false
	}
	for _, endpoint := range generated.Endpoints {
		if endpoint.Availability != generated.AvailabilityAvailable {
			continue
		}
		if implemented[endpoint.ID] != (registeredRoute{endpoint.Method, endpoint.Path}) {
			return false
		}
	}
	return true
}

func (app *Application) serve(writer http.ResponseWriter, request *http.Request) {
	if strings.HasPrefix(request.URL.Path, "/api/v") && !strings.HasPrefix(request.URL.Path, "/api/v1/") {
		app.failure(writer, "api", apiFailure(generated.ErrorCodeSchemaUnsupported, "schema-major"))
		return
	}
	if request.URL.Path == "/api/v1/events" && app.config.Streams != nil {
		app.serveEvents(writer, request)
		return
	}
	for _, candidate := range app.routes {
		params, ok := matchPath(candidate.pattern, request.URL.Path)
		if !ok {
			continue
		}
		if candidate.method == http.MethodGet && request.Method != candidate.method {
			app.failure(writer, candidate.id, apiFailure(generated.ErrorCodeInputInvalid, "method"))
			return
		}
		if strings.HasPrefix(candidate.id, "api.v1.session.") {
			if request.Method != candidate.method {
				app.failure(writer, candidate.id, apiFailure(generated.ErrorCodeInputInvalid, "method"))
				return
			}
			candidate.handler(writer, request, authorization.ReadScope{}, params)
			return
		}
		principal, ok := identity.PrincipalFromContext(request.Context())
		if !ok {
			app.failure(writer, candidate.id, apiFailure(generated.ErrorCodeAuthenticationRequired, "principal"))
			return
		}
		resourceID := ""
		if rawDraft, exists := params["draftId"]; exists {
			resourceID = rawDraft + ":" + params["revision"]
		}
		if candidate.id == "api.v1.inventory-drafts.import" {
			resourceID = "inventory-drafts"
		}
		scope, err := app.config.Authorizer.AuthorizeRead(request.Context(), principal, authorization.ReadTarget{Capability: candidate.capability, ResourceKind: candidate.kind, ResourceID: resourceID})
		if err != nil {
			app.failure(writer, candidate.id, err)
			return
		}
		if candidate.method == http.MethodPost && request.Method != candidate.method {
			app.failure(writer, candidate.id, apiFailure(generated.ErrorCodeInputInvalid, "method"))
			return
		}
		if candidate.method == http.MethodGet && request.Body != nil && request.ContentLength != 0 {
			app.failure(writer, candidate.id, apiFailure(generated.ErrorCodeInputInvalid, "request-body"))
			return
		}
		candidate.handler(writer, request, scope, params)
		return
	}
	app.failure(writer, "api", apiFailure(generated.ErrorCodeResourceNotFound, "route"))
}

func matchPath(pattern, path string) (map[string]string, bool) {
	want, got := strings.Split(strings.Trim(pattern, "/"), "/"), strings.Split(strings.Trim(path, "/"), "/")
	if len(want) != len(got) {
		return nil, false
	}
	params := map[string]string{}
	for i := range want {
		if strings.HasPrefix(want[i], "{") {
			params[strings.Trim(want[i], "{}")] = got[i]
			continue
		}
		if want[i] != got[i] {
			return nil, false
		}
	}
	return params, true
}

func parseRef(params map[string]string) (inventory.DraftRef, error) {
	revision, err := strconv.ParseInt(params["revision"], 10, 64)
	ref := inventory.DraftRef{ID: inventory.DraftID(params["draftId"]), Revision: revision}
	if err != nil || authorization.ResourceID(ref) == "" {
		return inventory.DraftRef{}, apiFailure(generated.ErrorCodeInputInvalid, "path")
	}
	return ref, nil
}

func (app *Application) databaseStatus(w http.ResponseWriter, r *http.Request, scope authorization.ReadScope, _ map[string]string) {
	value, err := app.config.Reads.DatabaseStatus(r.Context(), scope)
	if err != nil {
		app.failure(w, "api.v1.database-status.get", err)
		return
	}
	app.success(w, "api.v1.database-status.get", value.Revision.StateRevision, value.Revision.RecoveryEpoch, projectDatabaseStatus(value))
}

func (app *Application) summary(w http.ResponseWriter, r *http.Request, scope authorization.ReadScope, _ map[string]string) {
	value, err := app.config.Reads.Summary(r.Context(), scope)
	if err != nil {
		app.failure(w, "api.v1.summary.get", err)
		return
	}
	app.success(w, "api.v1.summary.get", value.StateRevision, value.RecoveryEpoch, projectSummary(value))
}

func (app *Application) sourceList(w http.ResponseWriter, r *http.Request, scope authorization.ReadScope, _ map[string]string) {
	const endpoint = "api.v1.sources.list"
	validated, err := app.config.Queries.Decode(r.URL.Query(), QuerySpec{EndpointID: endpoint, AllowedFilters: []string{"source", "state"}, AllowedSorts: []string{"id-asc", "id-desc"}, DefaultSort: "id-asc"})
	if err != nil {
		app.failure(w, endpoint, err)
		return
	}
	query, err := sourceListQuery(validated)
	if err != nil {
		app.failure(w, endpoint, err)
		return
	}
	snapshot, decoded, err := app.pageState(r, scope, endpoint, validated)
	if err != nil {
		app.failure(w, endpoint, err)
		return
	}
	query.EvaluationAt = app.config.Cursors.Now()
	if decoded != nil {
		position := decoded.Position
		query.EvaluationAt = decoded.EvaluationAt
		query.AfterID = readmodel.SourceID(position.ImmutableID)
		if query.EvaluationAt.IsZero() || len(position.SortValues) != 1 || position.SortValues[0] != position.ImmutableID || !readmodel.ValidSourceID(query.AfterID) {
			app.failure(w, endpoint, apiFailure(generated.ErrorCodeStateConflict, "cursor"))
			return
		}
	}
	page, err := app.config.Reads.ListSources(r.Context(), scope, query, snapshot)
	if err != nil {
		app.failure(w, endpoint, err)
		return
	}
	if query.EvaluationAt.IsZero() || !page.EvaluationAt.Equal(query.EvaluationAt) || page.Snapshot.StateRevision != snapshot.StateRevision || page.Snapshot.RecoveryEpoch != snapshot.RecoveryEpoch || len(page.Items) > query.Limit {
		app.failure(w, endpoint, apiFailure(generated.ErrorCodeIntegrityFailure, "source-page"))
		return
	}
	for _, item := range page.Items {
		if !readmodel.ValidSourceID(item.ID) || !readmodel.ValidSourceState(item.State) {
			app.failure(w, endpoint, apiFailure(generated.ErrorCodeIntegrityFailure, "source-page"))
			return
		}
	}
	var next *string
	if page.HasMore {
		if !readmodel.ValidSourceID(page.Last) {
			app.failure(w, endpoint, apiFailure(generated.ErrorCodeIntegrityFailure, "source-page"))
			return
		}
		binding := cursorBinding(endpoint, validated, scope, snapshot)
		binding.EvaluationAt = query.EvaluationAt
		token, encodeErr := app.config.Cursors.Encode(binding, CursorPosition{SortValues: []string{string(page.Last)}, ImmutableID: string(page.Last)})
		if encodeErr != nil {
			app.failure(w, endpoint, encodeErr)
			return
		}
		next = &token
	}
	app.success(w, endpoint, snapshot.StateRevision, snapshot.RecoveryEpoch, projectSourcePage(page, next))
}

func (app *Application) draftList(w http.ResponseWriter, r *http.Request, scope authorization.ReadScope, _ map[string]string) {
	const endpoint = "api.v1.inventory-drafts.list"
	query, err := app.config.Queries.Decode(r.URL.Query(), QuerySpec{EndpointID: endpoint, AllowedSorts: []string{"created-at-asc", "created-at-desc"}, DefaultSort: "created-at-asc"})
	if err != nil {
		app.failure(w, endpoint, err)
		return
	}
	snapshot, decoded, err := app.pageState(r, scope, endpoint, query)
	if err != nil {
		app.failure(w, endpoint, err)
		return
	}
	request := inventory.DraftListQuery{Limit: query.Limit, Sort: query.Sort}
	if decoded != nil {
		position := decoded.Position
		request.AfterCreatedAt, err = time.Parse(time.RFC3339Nano, position.SortValues[0])
		if err != nil {
			app.failure(w, endpoint, apiFailure(generated.ErrorCodeStateConflict, "cursor"))
			return
		}
		parts := strings.LastIndex(position.ImmutableID, ":")
		if parts < 1 {
			app.failure(w, endpoint, apiFailure(generated.ErrorCodeStateConflict, "cursor"))
			return
		}
		request.AfterDraftID = inventory.DraftID(position.ImmutableID[:parts])
		request.AfterRevision, err = strconv.ParseInt(position.ImmutableID[parts+1:], 10, 64)
		if err != nil {
			app.failure(w, endpoint, apiFailure(generated.ErrorCodeStateConflict, "cursor"))
			return
		}
	}
	page, err := app.config.Reads.ListDrafts(r.Context(), scope, request, snapshot)
	if err != nil {
		app.failure(w, endpoint, err)
		return
	}
	var next *string
	if page.HasMore && page.Last != nil {
		token, encodeErr := app.config.Cursors.Encode(cursorBinding(endpoint, query, scope, snapshot), CursorPosition{SortValues: []string{page.Last.AfterCreatedAt.UTC().Format(time.RFC3339Nano)}, ImmutableID: string(page.Last.AfterDraftID) + ":" + strconv.FormatInt(page.Last.AfterRevision, 10)})
		if encodeErr != nil {
			app.failure(w, endpoint, encodeErr)
			return
		}
		next = &token
	}
	app.success(w, endpoint, snapshot.StateRevision, snapshot.RecoveryEpoch, projectDraftPage(page, next))
}

func (app *Application) draftGet(w http.ResponseWriter, r *http.Request, scope authorization.ReadScope, params map[string]string) {
	const endpoint = "api.v1.inventory-drafts.get"
	ref, err := parseRef(params)
	if err != nil {
		app.failure(w, endpoint, err)
		return
	}
	value, err := app.config.Reads.GetDraft(r.Context(), scope, ref)
	if err != nil {
		app.failure(w, endpoint, err)
		return
	}
	health, err := app.config.Reads.CurrentRevision(r.Context(), scope)
	if err != nil {
		app.failure(w, endpoint, err)
		return
	}
	app.success(w, endpoint, health.StateRevision, health.RecoveryEpoch, projectDraft(value.Summary))
}

func (app *Application) recordList(kind string) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, scope authorization.ReadScope, params map[string]string) {
		endpoint := "api.v1.inventory-draft-" + kind + "s.list"
		ref, err := parseRef(params)
		if err != nil {
			app.failure(w, endpoint, err)
			return
		}
		query, err := app.config.Queries.Decode(r.URL.Query(), QuerySpec{EndpointID: endpoint, AllowedSorts: []string{"id-asc", "id-desc"}, DefaultSort: "id-asc"})
		if err != nil {
			app.failure(w, endpoint, err)
			return
		}
		snapshot, decoded, err := app.pageState(r, scope, endpoint, query)
		if err != nil {
			app.failure(w, endpoint, err)
			return
		}
		rq := inventory.RecordListQuery{AfterKind: kind, Limit: query.Limit, Sort: query.Sort}
		if decoded != nil {
			position := decoded.Position
			rq.AfterLocalID = inventory.LocalID(position.ImmutableID)
		}
		page, err := app.config.Reads.ListRecords(r.Context(), scope, ref, rq, snapshot)
		if err != nil {
			app.failure(w, endpoint, err)
			return
		}
		var next *string
		if page.HasMore && page.Last != nil {
			token, e := app.config.Cursors.Encode(cursorBinding(endpoint, query, scope, snapshot), CursorPosition{SortValues: []string{string(page.Last.AfterLocalID)}, ImmutableID: string(page.Last.AfterLocalID)})
			if e != nil {
				app.failure(w, endpoint, e)
				return
			}
			next = &token
		}
		app.success(w, endpoint, snapshot.StateRevision, snapshot.RecoveryEpoch, projectRecordPage(kind, page, next))
	}
}

func (app *Application) recordGet(kind string) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, scope authorization.ReadScope, params map[string]string) {
		endpoint := "api.v1.inventory-draft-" + kind + "s.get"
		ref, err := parseRef(params)
		if err != nil {
			app.failure(w, endpoint, err)
			return
		}
		if !pathToken.MatchString(params["recordId"]) {
			app.failure(w, endpoint, apiFailure(generated.ErrorCodeInputInvalid, "path"))
			return
		}
		value, err := app.config.Reads.GetRecord(r.Context(), scope, ref, kind, inventory.LocalID(params["recordId"]))
		if err != nil {
			app.failure(w, endpoint, err)
			return
		}
		revision, err := app.config.Reads.CurrentRevision(r.Context(), scope)
		if err != nil {
			app.failure(w, endpoint, err)
			return
		}
		app.success(w, endpoint, revision.StateRevision, revision.RecoveryEpoch, projectRecord(kind, value))
	}
}

func cursorBinding(endpoint string, query ValidatedQuery, scope authorization.ReadScope, snapshot store.RevisionToken) CursorBinding {
	return CursorBinding{SchemaMajor: 1, EndpointID: endpoint, QueryDigest: query.FilterDigest, ScopeDigest: scope.ScopeDigest, GrantRevision: scope.GrantRevision, Snapshot: snapshot}
}

func (app *Application) pageState(r *http.Request, scope authorization.ReadScope, endpoint string, query ValidatedQuery) (store.RevisionToken, *DecodedCursor, error) {
	if query.Cursor == "" {
		revision, err := app.config.Reads.CurrentRevision(r.Context(), scope)
		return revision, nil, err
	}
	binding := cursorBinding(endpoint, query, scope, store.RevisionToken{StateRevision: -1, RecoveryEpoch: -1})
	decoded, err := app.config.Cursors.Decode(query.Cursor, binding)
	if err != nil {
		return store.RevisionToken{}, nil, err
	}
	return decoded.Snapshot, &decoded, nil
}
