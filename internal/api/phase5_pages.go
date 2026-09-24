package api

import (
	"net/http"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type phase5PageState struct {
	Query    ValidatedQuery
	Snapshot store.RevisionToken
	AfterID  string
}

func (app *Application) phase5PageRequest(r *http.Request, scope authorization.ReadScope, endpoint string) (phase5PageState, error) {
	query, err := app.config.Queries.Decode(r.URL.Query(), QuerySpec{EndpointID: endpoint, AllowedSorts: []string{"id-asc"}, DefaultSort: "id-asc", DefaultLimit: 25, MaxLimit: 100})
	if err != nil {
		return phase5PageState{}, err
	}
	snapshot, decoded, err := app.pageState(r, scope, endpoint, query)
	if err != nil {
		return phase5PageState{}, err
	}
	state := phase5PageState{Query: query, Snapshot: snapshot}
	if decoded != nil {
		if len(decoded.Position.SortValues) != 1 || decoded.Position.ImmutableID == "" || decoded.Position.SortValues[0] != decoded.Position.ImmutableID || !pathToken.MatchString(decoded.Position.ImmutableID) {
			return phase5PageState{}, apiFailure(generated.ErrorCodeStateConflict, "cursor")
		}
		state.AfterID = decoded.Position.ImmutableID
	}
	return state, nil
}

func (app *Application) phase5NextCursor(endpoint string, scope authorization.ReadScope, state phase5PageState, lastID string, hasMore bool) (*string, error) {
	if !hasMore {
		return nil, nil
	}
	if !pathToken.MatchString(lastID) {
		return nil, apiFailure(generated.ErrorCodeIntegrityFailure, "page")
	}
	token, err := app.config.Cursors.Encode(cursorBinding(endpoint, state.Query, scope, state.Snapshot), CursorPosition{SortValues: []string{lastID}, ImmutableID: lastID})
	if err != nil {
		return nil, err
	}
	return &token, nil
}
