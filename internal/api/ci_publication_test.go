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
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func TestCIPublicationDeniedScopeNeverPrepares(t *testing.T) {
	for _, revoked := range []bool{false, true} {
		t.Run(map[bool]string{false: "no-grant", true: "revoked"}[revoked], func(t *testing.T) {
			snapshot := authorization.EffectivePolicySnapshot{PrincipalKind: identity.PrincipalHuman, Status: authorization.EffectiveActive, GrantRevision: 1, StateRevision: 1}
			if revoked {
				snapshot.Status = authorization.EffectiveRevoked
			}
			recorder := &authorizationRecorderStub{}
			app := newAuthorizationTestApplication(t, authorization.NewEvaluator(apiPolicyRepository{snapshot: snapshot}), recorder)
			calls := 0
			config := CIPublicationOperations{Jobs: &store.CIPublicationRepository{}, Credentials: &store.CredentialRepository{}, Declarations: &change.Service{}, Results: app.config.Results, Prepare: func(context.Context, generated.CiPublicationDraftRequest) (generated.DeclarationRevisionRequest, []credentialref.StepBinding, error) {
				calls++
				return generated.DeclarationRevisionRequest{}, nil, nil
			}}
			if err := RegisterCIPublicationOperations(app, config); err != nil {
				t.Fatal(err)
			}
			input := generated.CiPublicationDraftRequest{Schema: generated.SchemaIDCiPublicationDraftRequest, SchemaVersion: "1.0.0", BindingID: "publish-a", IdempotencyKey: "import-a", ReasonDigest: "sha256:" + strings.Repeat("a", 64)}
			raw, _ := json.Marshal(input)
			for _, tc := range []struct {
				method, path string
				body         []byte
			}{{"POST", "/api/v1/ci/publications/drafts", raw}} {
				req := httptest.NewRequest(tc.method, tc.path, bytes.NewReader(tc.body))
				req.Header.Set("Content-Type", "application/json")
				req = req.WithContext(identity.WithVerifiedPrincipal(req.Context(), identity.Principal{ID: "human-a", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}))
				response := httptest.NewRecorder()
				app.ServeHTTP(response, req)
				if response.Code != http.StatusForbidden || calls != 0 {
					t.Fatalf("%s status=%d calls=%d body=%s", tc.path, response.Code, calls, response.Body.String())
				}
			}
			if len(recorder.records) != 1 {
				t.Fatalf("authorization audit records=%d", len(recorder.records))
			}
		})
	}
}
