package api

import (
	"bytes"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/authorization"
)

func TestPhase5PageCursorBindsEndpointScopeQueryAndSnapshot(t *testing.T) {
	codec, err := NewCursorCodec(bytes.NewReader(bytes.Repeat([]byte{7}, 32)), func() time.Time { return time.Date(2026, 9, 24, 6, 0, 0, 0, time.UTC) })
	if err != nil {
		t.Fatal(err)
	}
	app := &Application{config: Config{Reads: testReads{}, Queries: NewQueryDecoder(), Cursors: codec}}
	scope := authorization.ReadScope{PrincipalID: "principal-a", Capability: "audit.checkpoint.read", ResourceKind: "audit-checkpoint", GrantRevision: 3, ScopeDigest: "sha256:scope-a"}
	first, err := app.phase5PageRequest(httptest.NewRequest("GET", "/api/v1/audit-checkpoints", nil), scope, "api.v1.audit-checkpoints.list")
	if err != nil || first.Query.Limit != 25 || first.AfterID != "" {
		t.Fatalf("default page = %#v err=%v", first, err)
	}
	first.Query, err = app.config.Queries.Decode(mapQuery("limit", "2"), QuerySpec{EndpointID: "api.v1.audit-checkpoints.list", AllowedSorts: []string{"id-asc"}, DefaultSort: "id-asc", DefaultLimit: 25, MaxLimit: 100})
	if err != nil {
		t.Fatal(err)
	}
	token, err := app.phase5NextCursor("api.v1.audit-checkpoints.list", scope, first, "checkpoint-a", true)
	if err != nil || token == nil {
		t.Fatal(err)
	}
	page, err := app.phase5PageRequest(httptest.NewRequest("GET", "/api/v1/audit-checkpoints?limit=2&cursor="+*token, nil), scope, "api.v1.audit-checkpoints.list")
	if err != nil || page.AfterID != "checkpoint-a" || page.Query.Limit != 2 {
		t.Fatalf("decoded page = %#v err=%v", page, err)
	}
	for _, changed := range []struct {
		endpoint string
		scope    authorization.ReadScope
	}{
		{"api.v1.recovery-points.list", scope},
		{"api.v1.audit-checkpoints.list", authorization.ReadScope{PrincipalID: "principal-b", Capability: scope.Capability, ResourceKind: scope.ResourceKind, GrantRevision: 4, ScopeDigest: "sha256:scope-b"}},
	} {
		request := httptest.NewRequest("GET", "/api/v1/audit-checkpoints?limit=2&cursor="+*token, nil)
		if _, err := app.phase5PageRequest(request, changed.scope, changed.endpoint); apiErrorCode(err) != "STATE_CONFLICT" {
			t.Fatalf("cross-binding %s error=%v", changed.endpoint, err)
		}
	}
	if _, err := app.phase5PageRequest(httptest.NewRequest("GET", "/api/v1/audit-checkpoints?limit=101", nil), scope, "api.v1.audit-checkpoints.list"); apiErrorCode(err) != "INPUT_INVALID" {
		t.Fatalf("limit error=%v", err)
	}
}

func mapQuery(key, value string) url.Values { return url.Values{key: []string{value}} }
