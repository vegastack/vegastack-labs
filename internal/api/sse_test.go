package api

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/readmodel"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type testSubscription struct{ c chan struct{} }

func (s *testSubscription) C() <-chan struct{} { return s.c }
func (s *testSubscription) Close() {
	select {
	case <-s.c:
	default:
		close(s.c)
	}
}

type testEventSource struct {
	cancel context.CancelFunc
	calls  int
}

func (s *testEventSource) ReadEvents(context.Context, authorization.ReadScope, audit.EventID, int) (readmodel.EventBatch, error) {
	s.calls++
	if s.calls == 1 {
		s.cancel()
		return readmodel.EventBatch{Items: []audit.Event{{Schema: audit.EventSchema, SchemaVersion: audit.EventSchemaVersion, EventID: 2, OccurredAt: "2026-09-09T12:00:00Z", RecoveryEpoch: 1, StateRevision: 2, Type: "inventory.created", CorrelationID: "correlation-test", PrincipalID: "principal.test", PrincipalMethod: identity.LocalOSPeerMethod, Target: audit.Target{Kind: "inventory-draft", ID: "draft-test"}}}}, nil
	}
	return readmodel.EventBatch{}, nil
}
func (*testEventSource) EventHighWater(context.Context, authorization.ReadScope) (audit.EventID, error) {
	return 1, nil
}
func (*testEventSource) EventExists(context.Context, authorization.ReadScope, audit.EventID) (bool, error) {
	return true, nil
}
func (*testEventSource) SubscribeEventCommits() store.EventSubscription {
	return &testSubscription{c: make(chan struct{}, 64)}
}

func TestSSEReplaysStrictlyAfterDurableIDAsGeneratedProjection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	source := &testEventSource{cancel: cancel}
	scope := authorization.ReadScope{PrincipalID: "principal.test", Capability: "audit.event.read", ResourceKind: "audit-event", GrantRevision: 1, ScopeDigest: "sha256:scope"}
	authorizer := authorizerFunc(func(context.Context, identity.Principal, authorization.ReadTarget) (authorization.ReadScope, error) {
		return scope, nil
	})
	streamer, err := NewEventStreamer(source, authorizer, ProductionStreamLimits)
	if err != nil {
		t.Fatal(err)
	}
	defer streamer.Close()
	request := httptest.NewRequest("GET", "/api/v1/events", nil).WithContext(ctx)
	request.Header.Set("Last-Event-ID", "1")
	response := httptest.NewRecorder()
	var pre error
	streamer.ServeHTTP(response, request, identity.Principal{ID: "principal.test", Method: identity.LocalOSPeerMethod}, scope, func(err error) { pre = err })
	if pre != nil {
		t.Fatal(pre)
	}
	body := response.Body.String()
	if !strings.Contains(body, "id: 2\nevent: audit-event\ndata: {\"event\":") || strings.Contains(body, "payload_bytes") {
		t.Fatalf("stream = %q", body)
	}
}

func TestSSERejectsInvalidResumeBeforeHeaders(t *testing.T) {
	_, cancel := context.WithCancel(context.Background())
	source := &testEventSource{cancel: cancel}
	scope := authorization.ReadScope{PrincipalID: "principal.test", GrantRevision: 1, ScopeDigest: "sha256:scope"}
	authorizer := authorizerFunc(func(context.Context, identity.Principal, authorization.ReadTarget) (authorization.ReadScope, error) {
		return scope, nil
	})
	streamer, _ := NewEventStreamer(source, authorizer, ProductionStreamLimits)
	defer streamer.Close()
	request := httptest.NewRequest("GET", "/api/v1/events", nil)
	request.Header.Set("Last-Event-ID", "0")
	response := httptest.NewRecorder()
	var pre error
	streamer.ServeHTTP(response, request, identity.Principal{ID: "principal.test", Method: identity.LocalOSPeerMethod}, scope, func(err error) { pre = err })
	if pre == nil || response.Code != 200 || response.Header().Get("Content-Type") != "" {
		t.Fatalf("pre/header = %v/%v", pre, response.Header())
	}
}

func TestProductionStreamLimitsAreBounded(t *testing.T) {
	if ProductionStreamLimits != (StreamLimits{200, 64, 15 * time.Second, 5 * time.Second, 16, 4}) {
		t.Fatalf("limits = %#v", ProductionStreamLimits)
	}
}
