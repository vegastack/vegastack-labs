package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func TestServiceDeniedScopeNeverCallsPreparationOrObservation(t *testing.T) {
	for _, revoked := range []bool{false, true} {
		t.Run(map[bool]string{false: "no-grant", true: "revoked"}[revoked], func(t *testing.T) {
			snapshot := authorization.EffectivePolicySnapshot{PrincipalKind: identity.PrincipalHuman, Status: authorization.EffectiveActive, GrantRevision: 1, StateRevision: 1}
			if revoked {
				snapshot.Status = authorization.EffectiveRevoked
			}
			recorder := &authorizationRecorderStub{}
			app := newAuthorizationTestApplication(t, authorization.NewEvaluator(apiPolicyRepository{snapshot: snapshot}), recorder)
			calls := 0
			config := ServicesOperations{Services: &store.ServiceRepository{}, Declarations: &change.Service{}, Results: app.config.Results, Prepare: func(context.Context, generated.ServiceImportDraftRequest) (generated.ServiceImportRequest, error) {
				calls++
				return generated.ServiceImportRequest{}, nil
			}, Observe: func(context.Context, string) (generated.ServiceObservation, error) {
				calls++
				return generated.ServiceObservation{}, nil
			}}
			if err := RegisterServiceOperations(app, config); err != nil {
				t.Fatal(err)
			}
			input := generated.ServiceImportDraftRequest{Schema: generated.SchemaIDServiceImportDraftRequest, SchemaVersion: "1.0.0", ServiceID: "service-a", BindingID: "binding-a", IdempotencyKey: "import-a", ReasonDigest: "sha256:" + strings.Repeat("a", 64)}
			raw, _ := json.Marshal(input)
			for _, tc := range []struct {
				method, path string
				body         []byte
			}{{"POST", "/api/v1/services/import-drafts", raw}, {"GET", "/api/v1/services/service-a/observation", nil}, {"GET", "/api/v1/services/service-a", nil}} {
				req := httptest.NewRequest(tc.method, tc.path, bytes.NewReader(tc.body))
				req.Header.Set("Content-Type", "application/json")
				req = req.WithContext(identity.WithVerifiedPrincipal(req.Context(), identity.Principal{ID: "human-a", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}))
				response := httptest.NewRecorder()
				app.ServeHTTP(response, req)
				if response.Code != http.StatusForbidden || calls != 0 {
					t.Fatalf("%s status=%d calls=%d body=%s", tc.path, response.Code, calls, response.Body.String())
				}
			}
			if len(recorder.records) != 3 {
				t.Fatalf("authorization audit records=%d", len(recorder.records))
			}
		})
	}
}

func TestServiceListQueryIsStrictAndBounded(t *testing.T) {
	for _, query := range []string{"limit=0", "limit=101", "limit=-1", "limit=1&limit=2", "after=service-a&after=service-b", "unknown=x", "after=", "after=../private", "limit=1.0", "limit=%ZZ"} {
		if _, _, err := serviceListQuery(query); err == nil {
			t.Fatalf("accepted %q", query)
		}
	}
	for _, query := range []string{"", "after=service-a", "after=service-a&limit=100", "limit=1"} {
		after, limit, err := serviceListQuery(query)
		if err != nil || limit < 1 || limit > 100 {
			t.Fatalf("%q after=%s limit=%d err=%v", query, after, limit, err)
		}
	}
}

func TestServiceBrowserReadSurfaceExcludesImportMutation(t *testing.T) {
	for _, path := range []string{"/api/v1/services", "/api/v1/services/service-a", "/api/v1/services/service-a/observation"} {
		if !RemoteReadRequestAllowed(http.MethodGet, path) {
			t.Fatalf("missing browser read %s", path)
		}
	}
	if RemoteReadRequestAllowed(http.MethodPost, "/api/v1/services/import-drafts") {
		t.Fatal("operator-only import exposed to browser")
	}
}
