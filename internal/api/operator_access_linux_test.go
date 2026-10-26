//go:build linux

package api

import (
	"context"
	"database/sql"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/store"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOperatorAccessAPIRealScopedRepository(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "control.db")
	authority, err := store.Open(context.Background(), store.Config{DatabasePath: path, Mode: store.InitializeNew, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "1.0.0", BuildVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	db, err := sql.Open("sqlite3", "file:"+path+"?mode=rw")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"operator", "person-a", "private-person"} {
		exec(`INSERT INTO effective_authorization_principals VALUES(?,'human','active',1,'now','now')`, id)
		exec(`INSERT INTO read_principals VALUES(?,'active',1,'now','now')`, id)
	}
	exec(`INSERT INTO effective_authorization_grants VALUES('policy-read','operator','reader','read','authorization.policy.read','authorization-policy','person-a',NULL,1,'active','now','now')`)
	exec(`INSERT INTO operator_devices VALUES('device-a','person-a','approved',1,'now','now')`)
	exec(`INSERT INTO read_grants VALUES('operator','platform.source.read','platform-source','providers',1,'active','now','now')`)
	app := newAuthorizationTestApplication(t, authorization.NewEvaluator(store.NewEffectiveAuthorizationRepository(authority)), &authorizationRecorderStub{})
	app.config.Authorizer = store.NewReadAuthorizer(authority)
	repo := store.NewOperatorAccessRepository(authority)
	if err := RegisterOperatorAccessOperations(app, repo); err != nil {
		t.Fatal(err)
	}
	if err := RegisterProviderReadOperations(app, repo, ProviderConfiguration{Identity: true}); err != nil {
		t.Fatal(err)
	}
	request := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", path, nil)
		req = req.WithContext(identity.WithVerifiedPrincipal(req.Context(), identity.Principal{ID: "operator", Kind: identity.PrincipalHuman, Method: identity.LocalOSPeerMethod}))
		w := httptest.NewRecorder()
		app.ServeHTTP(w, req)
		return w
	}
	for _, path := range []string{"/api/v1/people?limit=1", "/api/v1/devices?principalId=person-a", "/api/v1/grants?principalId=person-a", "/api/v1/providers"} {
		w := request(path)
		if w.Code != 200 || strings.Contains(w.Body.String(), "private-person") {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
	}
	w := request("/api/v1/providers")
	if !strings.Contains(w.Body.String(), `"configured":true,"connectivity":"unknown"`) || !strings.Contains(w.Body.String(), `"configured":false,"connectivity":"unavailable"`) || strings.Contains(w.Body.String(), "healthy") {
		t.Fatal(w.Body.String())
	}
	for _, path := range []string{"/api/v1/devices?principalId=private-person", "/api/v1/grants?principalId=private-person"} {
		if w := request(path); w.Code != 403 {
			t.Fatalf("cross-owner %s: %d", path, w.Code)
		}
	}
	exec(`UPDATE effective_authorization_principals SET status='suspended' WHERE principal_id='operator'`)
	for _, path := range []string{"/api/v1/people", "/api/v1/devices?principalId=person-a", "/api/v1/grants?principalId=person-a", "/api/v1/providers"} {
		if w := request(path); w.Code != 403 {
			t.Fatalf("suspended %s: %d %s", path, w.Code, w.Body.String())
		}
	}
}
