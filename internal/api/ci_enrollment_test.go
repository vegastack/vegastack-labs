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

func TestCIEnrollmentDeniedScopeNeverPrepares(t *testing.T) {
	for _, revoked := range []bool{false, true} {
		t.Run(map[bool]string{false: "no-grant", true: "revoked"}[revoked], func(t *testing.T) {
			snapshot := authorization.EffectivePolicySnapshot{PrincipalKind: identity.PrincipalHuman, Status: authorization.EffectiveActive, GrantRevision: 1, StateRevision: 1}
			if revoked {
				snapshot.Status = authorization.EffectiveRevoked
			}
			recorder := &authorizationRecorderStub{}
			app := newAuthorizationTestApplication(t, authorization.NewEvaluator(apiPolicyRepository{snapshot: snapshot}), recorder)
			calls := 0
			config := CIEnrollmentOperations{Enrollments: &store.CIEnrollmentRepository{}, Declarations: &change.Service{}, Results: app.config.Results, Prepare: func(context.Context, generated.CiEnrollmentDraftRequest) (generated.CiEnrollmentRequest, error) {
				calls++
				return generated.CiEnrollmentRequest{}, nil
			}}
			if err := RegisterCIEnrollmentOperations(app, config); err != nil {
				t.Fatal(err)
			}
			input := generated.CiEnrollmentDraftRequest{Schema: generated.SchemaIDCiEnrollmentDraftRequest, SchemaVersion: "1.0.0", EnrollmentID: "service-a", BindingID: "binding-a", IdempotencyKey: "import-a", ReasonDigest: "sha256:" + strings.Repeat("a", 64)}
			raw, _ := json.Marshal(input)
			for _, tc := range []struct {
				method, path string
				body         []byte
			}{{"POST", "/api/v1/ci/enrollments/drafts", raw}, {"GET", "/api/v1/ci/enrollments/enrollment-a", nil}} {
				req := httptest.NewRequest(tc.method, tc.path, bytes.NewReader(tc.body))
				req.Header.Set("Content-Type", "application/json")
				req = req.WithContext(identity.WithVerifiedPrincipal(req.Context(), identity.Principal{ID: "human-a", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}))
				response := httptest.NewRecorder()
				app.ServeHTTP(response, req)
				if response.Code != http.StatusForbidden || calls != 0 {
					t.Fatalf("%s status=%d calls=%d body=%s", tc.path, response.Code, calls, response.Body.String())
				}
			}
			if len(recorder.records) != 2 {
				t.Fatalf("authorization audit records=%d", len(recorder.records))
			}
		})
	}
}

func TestCIEnrollmentListQueryIsStrictAndBounded(t *testing.T) {
	for _, query := range []string{"limit=0", "limit=101", "limit=-1", "limit=1&limit=2", "after=service-a&after=service-b", "unknown=x", "after=", "after=../private", "limit=1.0", "limit=%ZZ"} {
		if _, _, err := ciEnrollmentListQuery(query); err == nil {
			t.Fatalf("accepted %q", query)
		}
	}
	for _, query := range []string{"", "after=service-a", "after=service-a&limit=100", "limit=1"} {
		after, limit, err := ciEnrollmentListQuery(query)
		if err != nil || limit < 1 || limit > 100 {
			t.Fatalf("%q after=%s limit=%d err=%v", query, after, limit, err)
		}
	}
}
