package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

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
	return readmodel.Summary{DatabaseMode: "safe-mode", ReadAvailable: true, MutationAvailable: false, DraftCount: 3, LastEventID: 9, RecoveryEpoch: 2, StateRevision: 7}, nil
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
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" || !strings.Contains(response.Body.String(), `"command":"api.v1.summary.get"`) || !strings.Contains(response.Body.String(), `"databaseMode":"safe-mode"`) {
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
