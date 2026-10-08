package api

import (
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/store"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHostAdoptionAPIRejectsUntrustedInputs(t *testing.T) {
	app := newAuthorizationTestApplication(t, authorization.NewEvaluator(apiPolicyRepository{snapshot: authorization.EffectivePolicySnapshot{PrincipalKind: identity.PrincipalHuman, Status: authorization.EffectiveActive, GrantRevision: 1}}), &authorizationRecorderStub{})
	if err := RegisterHostAdoptionOperations(app, HostAdoptionOperations{Hosts: store.NewHostAdoptionRepository(nil), Declarations: &change.Service{}, Results: app.config.Results}); err != nil {
		t.Fatal(err)
	}
	req := generated.HostAdoptionRequest{Schema: generated.SchemaIDHostAdoptionRequest, SchemaVersion: "1.0.0", HostID: "synthetic-host", ObservationID: "synthetic-observation", ObservationDigest: "sha256:" + strings.Repeat("a", 64), IdempotencyKey: "draft-one", Confirmation: generated.HostIdentityConfirmation{Schema: generated.SchemaIDHostIdentityConfirmation, SchemaVersion: "1.0.0", TargetRevision: 1, TargetDigest: "sha256:" + strings.Repeat("b", 64), IdentityDigest: "sha256:" + strings.Repeat("c", 64), IdentityClass: "physical", IdentityKind: "product-serial", ConfirmedAt: "2026-10-08T00:00:00Z"}}
	raw, _ := json.Marshal(req)
	good := string(raw)
	if err := generated.ValidateContractJSON(generated.SchemaIDHostAdoptionRequest, raw, generated.ContractExact); err != nil {
		t.Fatal("invalid control fixture", err)
	}
	top := strings.TrimSuffix(good, "}") + `,"extra":"private-canary"}`
	nested := strings.Replace(good, `"confirmation":{`, `"confirmation":{"extra":"private-canary",`, 1)
	for _, tc := range []struct {
		body   string
		status int
	}{{good, http.StatusForbidden}, {top, http.StatusBadRequest}, {nested, http.StatusBadRequest}, {strings.Repeat(" ", 16385) + good, http.StatusBadRequest}} {
		body := tc.body
		r := httptest.NewRequest("POST", "/api/v1/host-adoptions/draft", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r = r.WithContext(identity.WithVerifiedPrincipal(r.Context(), identity.Principal{ID: "operator-a", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}))
		w := httptest.NewRecorder()
		app.ServeHTTP(w, r)
		if w.Code != tc.status || strings.Contains(w.Body.String(), "private-canary") {
			t.Fatalf("invalid request status %d: %s", w.Code, w.Body.String())
		}
	}
	r := httptest.NewRequest("GET", "/api/v1/hosts/synthetic-host", nil)
	w := httptest.NewRecorder()
	app.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatal("anonymous host read allowed")
	}
}
