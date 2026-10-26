package api

import (
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/store"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOperatorAccessAPIRejectsUntrustedQueryAndMissingScope(t *testing.T) {
	app := newAuthorizationTestApplication(t, authorization.NewEvaluator(apiPolicyRepository{snapshot: authorization.EffectivePolicySnapshot{PrincipalKind: identity.PrincipalHuman, Status: authorization.EffectiveActive, GrantRevision: 1}}), &authorizationRecorderStub{})
	if e := RegisterOperatorAccessOperations(app, store.NewOperatorAccessRepository(nil)); e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		path   string
		actor  bool
		status int
	}{{"/api/v1/people", false, 401}, {"/api/v1/people", true, 403}, {"/api/v1/people?principalId=private-canary", true, 400}, {"/api/v1/people?limit=101", true, 400}, {"/api/v1/people?limit=1&limit=2", true, 400}, {"/api/v1/devices", true, 400}, {"/api/v1/devices?principalId=person-a&extra=private-canary", true, 400}, {"/api/v1/grants?principalId=person-a", true, 403}} {
		req := httptest.NewRequest("GET", tc.path, nil)
		if tc.actor {
			req = req.WithContext(identity.WithVerifiedPrincipal(req.Context(), identity.Principal{ID: "operator", Kind: identity.PrincipalHuman, Method: identity.LocalOSPeerMethod}))
		}
		w := httptest.NewRecorder()
		app.ServeHTTP(w, req)
		if w.Code != tc.status || strings.Contains(w.Body.String(), "private-canary") {
			t.Fatalf("%s: %d %s", tc.path, w.Code, w.Body.String())
		}
	}
}
