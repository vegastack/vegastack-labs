package api

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMaintenanceDeniedAndRevokedScopeNeverReadsOrDrafts(t *testing.T) {
	for _, status := range []authorization.EffectiveStatus{authorization.EffectiveActive, authorization.EffectiveRevoked} {
		snapshot := authorization.EffectivePolicySnapshot{PrincipalKind: identity.PrincipalHuman, Status: status, GrantRevision: 1, StateRevision: 1}
		app := newAuthorizationTestApplication(t, authorization.NewEvaluator(apiPolicyRepository{snapshot: snapshot}), &authorizationRecorderStub{})
		calls := 0
		c := MaintenanceOperations{Declarations: &fakeDeclarationService{}, Results: app.config.Results, Diagnose: func(context.Context, string) (generated.MaintenanceDiagnosis, error) {
			calls++
			return generated.MaintenanceDiagnosis{}, nil
		}, Prepare: func(context.Context, generated.MaintenanceDraftRequest, string) (generated.DeclarationRevisionRequest, error) {
			calls++
			return generated.DeclarationRevisionRequest{}, nil
		}}
		if e := RegisterMaintenanceOperations(app, c); e != nil {
			t.Fatal(e)
		}
		q := generated.MaintenanceDraftRequest{Schema: generated.SchemaIDMaintenanceDraftRequest, SchemaVersion: "1.0.0", DeclarationID: "maintenance-a", ExpectedRevision: 1, TargetIDs: []string{"host-a"}, CanaryHostID: "host-a", Action: "repair", ReasonDigest: hostaction.Digest("reason")}
		raw, _ := json.Marshal(q)
		for _, tc := range []struct {
			method, path string
			body         []byte
		}{{"GET", "/api/v1/maintenance/hosts/host-a", nil}, {"POST", "/api/v1/maintenance/drafts", raw}} {
			req := httptest.NewRequest(tc.method, tc.path, bytes.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			req = req.WithContext(identity.WithVerifiedPrincipal(req.Context(), identity.Principal{ID: "human-a", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}))
			w := httptest.NewRecorder()
			app.ServeHTTP(w, req)
			if w.Code != http.StatusForbidden || calls != 0 {
				t.Fatal(w.Code, w.Body.String(), calls)
			}
		}
	}
}
