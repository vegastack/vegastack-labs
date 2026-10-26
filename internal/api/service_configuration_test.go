package api

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServiceConfigurationDenialBeforeProvider(t *testing.T) {
	for _, revoked := range []bool{false, true} {
		snapshot := authorization.EffectivePolicySnapshot{PrincipalKind: identity.PrincipalHuman, Status: authorization.EffectiveActive, GrantRevision: 1, StateRevision: 1}
		if revoked {
			snapshot.Status = authorization.EffectiveRevoked
		}
		app := newAuthorizationTestApplication(t, authorization.NewEvaluator(apiPolicyRepository{snapshot: snapshot}), &authorizationRecorderStub{})
		calls := 0
		if e := RegisterServiceConfigurationOperations(app, ServiceConfigurationOperations{Configuration: func(context.Context, string) (generated.ServiceConfigurationStatus, error) {
			calls++
			return generated.ServiceConfigurationStatus{}, nil
		}}); e != nil {
			t.Fatal(e)
		}
		req := httptest.NewRequest(http.MethodGet, "/api/v1/services/service-a/configuration", nil)
		req = req.WithContext(identity.WithVerifiedPrincipal(req.Context(), identity.Principal{ID: "human-a", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}))
		response := httptest.NewRecorder()
		app.ServeHTTP(response, req)
		if response.Code != http.StatusForbidden || calls != 0 {
			t.Fatal(response.Code, calls)
		}
	}
}
