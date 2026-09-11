package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/inventory"
	"github.com/vegastack/vegastack-labs/internal/readmodel"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type authorizerFunc func(context.Context, identity.Principal, authorization.ReadTarget) (authorization.ReadScope, error)

func (fn authorizerFunc) AuthorizeRead(ctx context.Context, principal identity.Principal, target authorization.ReadTarget) (authorization.ReadScope, error) {
	return fn(ctx, principal, target)
}

type queryDecoderFunc func(url.Values, QuerySpec) (ValidatedQuery, error)

func (fn queryDecoderFunc) Decode(values url.Values, spec QuerySpec) (ValidatedQuery, error) {
	return fn(values, spec)
}

type testAuthority struct{}

func (testAuthority) Health(context.Context) (store.Health, error) { return store.Health{}, nil }
func (testAuthority) Close() error                                 { return nil }

type testReads struct{ onCall func() }

func (r testReads) call() {
	if r.onCall != nil {
		r.onCall()
	}
}
func (r testReads) CurrentRevision(context.Context, authorization.ReadScope) (store.RevisionToken, error) {
	r.call()
	return store.RevisionToken{}, nil
}
func (r testReads) DatabaseStatus(context.Context, authorization.ReadScope) (readmodel.DatabaseStatus, error) {
	r.call()
	return readmodel.DatabaseStatus{}, nil
}
func (r testReads) Summary(context.Context, authorization.ReadScope) (readmodel.Summary, error) {
	r.call()
	return readmodel.Summary{}, nil
}
func (r testReads) ListSources(context.Context, authorization.ReadScope, readmodel.SourceListQuery, store.RevisionToken) (readmodel.SourcePage, error) {
	r.call()
	return readmodel.SourcePage{}, nil
}
func (r testReads) ListDrafts(context.Context, authorization.ReadScope, inventory.DraftListQuery, store.RevisionToken) (readmodel.DraftPage, error) {
	r.call()
	return readmodel.DraftPage{}, nil
}
func (r testReads) GetDraft(context.Context, authorization.ReadScope, inventory.DraftRef) (readmodel.Draft, error) {
	r.call()
	return readmodel.Draft{}, nil
}
func (r testReads) ListRecords(context.Context, authorization.ReadScope, inventory.DraftRef, inventory.RecordListQuery, store.RevisionToken) (readmodel.RecordPage, error) {
	r.call()
	return readmodel.RecordPage{}, nil
}
func (r testReads) GetRecord(context.Context, authorization.ReadScope, inventory.DraftRef, string, inventory.LocalID) (readmodel.Record, error) {
	r.call()
	return readmodel.Record{}, nil
}
func (r testReads) ReadEvents(context.Context, authorization.ReadScope, audit.EventID, int) (readmodel.EventBatch, error) {
	r.call()
	return readmodel.EventBatch{}, nil
}
func (r testReads) EventHighWater(context.Context, authorization.ReadScope) (audit.EventID, error) {
	r.call()
	return 0, nil
}
func (r testReads) EventExists(context.Context, authorization.ReadScope, audit.EventID) (bool, error) {
	r.call()
	return false, nil
}

type testCursor struct{}

func (testCursor) Encode(CursorBinding, CursorPosition) (string, error) { return "cursor", nil }
func (testCursor) Decode(string, CursorBinding) (DecodedCursor, error)  { return DecodedCursor{}, nil }
func (testCursor) Now() time.Time                                       { return time.Date(2026, 9, 10, 8, 0, 0, 0, time.UTC) }

func TestHandlerAuthorizesBeforeQueryCursorOrResourceLookup(t *testing.T) {
	var calls []string
	app, err := NewApplication(Config{
		Authority: testAuthority{},
		Authorizer: authorizerFunc(func(context.Context, identity.Principal, authorization.ReadTarget) (authorization.ReadScope, error) {
			calls = append(calls, "authorize")
			return authorization.ReadScope{}, failure.New(generated.ErrorCodeAuthorizationDenied, "read", false)
		}),
		Reads:   testReads{onCall: func() { calls = append(calls, "lookup") }},
		Results: result.NewFactory(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}, func() (string, error) { return "request-test", nil }),
		Cursors: testCursor{},
		Queries: queryDecoderFunc(func(url.Values, QuerySpec) (ValidatedQuery, error) {
			calls = append(calls, "query")
			return ValidatedQuery{}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/inventory-drafts?unknown=secret-canary&cursor=broken", nil)
	request = request.WithContext(identity.WithVerifiedPrincipal(request.Context(), identity.Principal{ID: "principal.test", Method: identity.LocalOSPeerMethod}))
	response := httptest.NewRecorder()
	app.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || !reflect.DeepEqual(calls, []string{"authorize"}) {
		t.Fatalf("status/calls = %d/%v", response.Code, calls)
	}
	if strings.Contains(response.Body.String(), "secret-canary") {
		t.Fatal("denial echoed protected query")
	}
}

type summaryReads struct{ testReads }

func (summaryReads) Summary(context.Context, authorization.ReadScope) (readmodel.Summary, error) {
	return readmodel.Summary{DatabaseMode: "safe-mode", ReadAvailable: true, MutationAvailable: false, DraftCount: 3, LastEventID: 9, RecoveryEpoch: 2, StateRevision: 7, SourceCounts: readmodel.SourceCounts{Total: 7, Healthy: 1, Unknown: 1, Unavailable: 5}, WorstSourceState: readmodel.SourceUnknown}, nil
}

type sourceReads struct {
	testReads
	queries []readmodel.SourceListQuery
}

func (reads *sourceReads) CurrentRevision(context.Context, authorization.ReadScope) (store.RevisionToken, error) {
	return store.RevisionToken{StateRevision: 7, RecoveryEpoch: 2}, nil
}

func (reads *sourceReads) ListSources(_ context.Context, _ authorization.ReadScope, query readmodel.SourceListQuery, snapshot store.RevisionToken) (readmodel.SourcePage, error) {
	reads.queries = append(reads.queries, query)
	recent := time.Date(2026, time.September, 10, 8, 0, 0, 0, time.UTC)
	items := []readmodel.SourceStatus{{ID: readmodel.SourceServices, Capability: "secret-capability", State: readmodel.SourceFailed, CollectedAt: &recent, LastSuccessAt: &recent, Reason: "provider-secret"}}
	hasMore := query.AfterID == ""
	if !hasMore {
		items = []readmodel.SourceStatus{}
	}
	return readmodel.SourcePage{
		Items:        items,
		HasMore:      hasMore,
		Last:         readmodel.SourceServices,
		EvaluationAt: query.EvaluationAt,
		Snapshot: readmodel.RevisionToken{
			StateRevision: snapshot.StateRevision,
			RecoveryEpoch: snapshot.RecoveryEpoch,
		},
	}, nil
}

func TestSourcesAuthorizesBeforeInvalidFilters(t *testing.T) {
	var calls []string
	app, err := NewApplication(Config{
		Authority: testAuthority{},
		Authorizer: authorizerFunc(func(context.Context, identity.Principal, authorization.ReadTarget) (authorization.ReadScope, error) {
			calls = append(calls, "authorize")
			return authorization.ReadScope{}, failure.New(generated.ErrorCodeAuthorizationDenied, "read", false)
		}),
		Reads:   testReads{onCall: func() { calls = append(calls, "lookup") }},
		Results: result.NewFactory(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}, func() (string, error) { return "request-test", nil }),
		Cursors: testCursor{},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/sources?state=not-a-state&source=secret-canary", nil)
	request = request.WithContext(identity.WithVerifiedPrincipal(request.Context(), identity.Principal{ID: "principal.test", Method: identity.LocalOSPeerMethod}))
	response := httptest.NewRecorder()
	app.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || !reflect.DeepEqual(calls, []string{"authorize"}) || strings.Contains(response.Body.String(), "secret-canary") {
		t.Fatalf("response = %d/%v/%s", response.Code, calls, response.Body.String())
	}
}

func TestSourcesServeOnlyTheBoundedFilteredState(t *testing.T) {
	reads := &sourceReads{}
	scope := authorization.ReadScope{PrincipalID: "principal.test", Capability: "platform.source.read", ResourceKind: "platform-source", GrantRevision: 1, ScopeDigest: "sha256:scope"}
	app, err := NewApplication(Config{
		Authority: testAuthority{},
		Authorizer: authorizerFunc(func(_ context.Context, _ identity.Principal, target authorization.ReadTarget) (authorization.ReadScope, error) {
			if target != (authorization.ReadTarget{Capability: "platform.source.read", ResourceKind: "platform-source"}) {
				t.Fatalf("target = %#v", target)
			}
			return scope, nil
		}),
		Reads: reads, Results: result.NewFactory(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}, func() (string, error) { return "request-test", nil }), Cursors: testCursor{},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/sources?limit=5&sort=id-desc&source=services&state=failed", nil)
	request = request.WithContext(identity.WithVerifiedPrincipal(request.Context(), identity.Principal{ID: "principal.test", Method: identity.LocalOSPeerMethod}))
	response := httptest.NewRecorder()
	app.ServeHTTP(response, request)
	body := response.Body.String()
	query := reads.queries[0]
	if response.Code != http.StatusOK || query.Limit != 5 || query.Sort != "id-desc" || query.Source != readmodel.SourceServices || query.State != readmodel.SourceFailed {
		t.Fatalf("response/query = %d/%#v/%s", response.Code, query, body)
	}
	for _, want := range []string{`"state":"failed"`, `"nextCursor":"cursor"`, `"capability":"service.read"`} {
		if !strings.Contains(body, want) {
			t.Errorf("response missing %s: %s", want, body)
		}
	}
	if strings.Contains(body, "provider-secret") || strings.Contains(body, "secret-capability") {
		t.Fatalf("unsafe fixture data escaped: %s", body)
	}
	for _, unwanted := range []string{`"state":"healthy"`, `"state":"stale"`, `"state":"unknown"`, `"state":"unavailable"`} {
		if strings.Contains(body, unwanted) {
			t.Fatalf("filtered response contained %s: %s", unwanted, body)
		}
	}
}

func TestSourceCursorKeepsTheInitialEvaluationTimeAndRejectsTamperOrExpiry(t *testing.T) {
	now := time.Date(2026, 9, 10, 8, 0, 0, 0, time.UTC)
	codec, err := NewCursorCodec(bytes.NewReader(bytes.Repeat([]byte{9}, 32)), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	reads := &sourceReads{}
	scope := authorization.ReadScope{PrincipalID: "principal.test", Capability: "platform.source.read", ResourceKind: "platform-source", GrantRevision: 1, ScopeDigest: "sha256:scope"}
	app, err := NewApplication(Config{
		Authority: testAuthority{},
		Authorizer: authorizerFunc(func(context.Context, identity.Principal, authorization.ReadTarget) (authorization.ReadScope, error) {
			return scope, nil
		}),
		Reads: reads, Results: result.NewFactory(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}, func() (string, error) { return "request-test", nil }), Cursors: codec,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/sources?limit=1&sort=id-asc&source=services&state=failed"
	serve := func(path string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request = request.WithContext(identity.WithVerifiedPrincipal(request.Context(), identity.Principal{ID: "principal.test", Method: identity.LocalOSPeerMethod}))
		response := httptest.NewRecorder()
		app.ServeHTTP(response, request)
		return response
	}
	first := serve(path)
	var envelope generated.RunResult
	var data generated.ApiSourceListData
	if err := json.Unmarshal(first.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(envelope.Data, &data); err != nil || data.NextCursor == nil {
		t.Fatalf("first page = %#v, %v, %s", data, err, first.Body.String())
	}
	initialEvaluationAt := reads.queries[0].EvaluationAt
	now = now.Add(10 * time.Minute)
	second := serve(path + "&cursor=" + url.QueryEscape(*data.NextCursor))
	if second.Code != http.StatusOK || len(reads.queries) != 2 || !reads.queries[1].EvaluationAt.Equal(initialEvaluationAt) || reads.queries[1].AfterID != readmodel.SourceServices {
		t.Fatalf("second page/evaluation = %d/%#v/%s", second.Code, reads.queries, second.Body.String())
	}
	tampered := (*data.NextCursor)[:len(*data.NextCursor)-1] + "A"
	if tampered == *data.NextCursor {
		tampered = (*data.NextCursor)[:len(*data.NextCursor)-1] + "B"
	}
	if response := serve(path + "&cursor=" + url.QueryEscape(tampered)); response.Code != http.StatusConflict || len(reads.queries) != 2 {
		t.Fatalf("tampered cursor = %d/%d/%s", response.Code, len(reads.queries), response.Body.String())
	}
	now = initialEvaluationAt.Add(CursorLifetime + time.Second)
	if response := serve(path + "&cursor=" + url.QueryEscape(*data.NextCursor)); response.Code != http.StatusConflict || len(reads.queries) != 2 {
		t.Fatalf("expired cursor = %d/%d/%s", response.Code, len(reads.queries), response.Body.String())
	}
}

func TestProjectSourcePagePreservesAnExplicitEmptyCollection(t *testing.T) {
	page := projectSourcePage(readmodel.SourcePage{Snapshot: readmodel.RevisionToken{StateRevision: 7, RecoveryEpoch: 2}}, nil)
	if page.Items == nil || len(page.Items) != 0 || page.NextCursor != nil || page.StateRevision != 7 || page.RecoveryEpoch != 2 {
		t.Fatalf("empty page = %#v", page)
	}
}

func TestSummaryUsesGeneratedEnvelopeAndNoStoreCaching(t *testing.T) {
	scope := authorization.ReadScope{PrincipalID: "principal.test", Capability: "platform.summary.read", ResourceKind: "platform-summary", GrantRevision: 1, ScopeDigest: "sha256:scope"}
	app, err := NewApplication(Config{Authority: testAuthority{}, Authorizer: authorizerFunc(func(_ context.Context, _ identity.Principal, target authorization.ReadTarget) (authorization.ReadScope, error) {
		if target.Capability != "platform.summary.read" {
			t.Fatalf("target = %#v", target)
		}
		return scope, nil
	}), Reads: summaryReads{}, Results: result.NewFactory(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}, func() (string, error) { return "request-test", nil }), Cursors: testCursor{}})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/summary", nil)
	request = request.WithContext(identity.WithVerifiedPrincipal(request.Context(), identity.Principal{ID: "principal.test", Method: identity.LocalOSPeerMethod}))
	response := httptest.NewRecorder()
	app.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" || !strings.Contains(response.Body.String(), `"command":"api.v1.summary.get"`) || !strings.Contains(response.Body.String(), `"databaseMode":"safe-mode"`) || !strings.Contains(response.Body.String(), `"sourceCounts":{"total":7,"healthy":1`) || !strings.Contains(response.Body.String(), `"worstSourceState":"unknown"`) {
		t.Fatalf("response = %d %v %s", response.Code, response.Header(), response.Body.String())
	}
}

func TestFiniteResponseRejectsBodyOverFourMiB(t *testing.T) {
	app := &Application{config: Config{Results: result.NewFactory(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}, func() (string, error) { return "request-test", nil })}}
	response := httptest.NewRecorder()
	app.success(response, "api.test", 0, 0, map[string]string{"value": strings.Repeat("x", maxFiniteResponseBytes)})
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), strings.Repeat("x", 100)) {
		t.Fatalf("response = %d/%d", response.Code, response.Body.Len())
	}
}
