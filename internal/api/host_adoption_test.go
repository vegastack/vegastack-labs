package api

import (
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
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
	for _, body := range []string{`{}`, `{"schema":"vegastack-labs.dev/host-adoption-request","extra":"private-canary"}`, strings.Repeat(" ", 16385) + `{}`} {
		r := httptest.NewRequest("POST", "/api/v1/host-adoptions/draft", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r = r.WithContext(identity.WithVerifiedPrincipal(r.Context(), identity.Principal{ID: "operator-a", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}))
		w := httptest.NewRecorder()
		app.ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), "private-canary") {
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
