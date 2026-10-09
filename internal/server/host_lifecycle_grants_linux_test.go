//go:build linux

package server

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	planengine "github.com/vegastack/vegastack-labs/internal/plan"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/store"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// The external assertion/session boundary is synthetic; current authorization,
// HTTP route handling, denial recording and private host lookup use real SQLite.
func TestHostLifecycleBrowserCurrentStoreGrants(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "control.db")
	authority, err := store.Open(context.Background(), store.Config{DatabasePath: path, Mode: store.InitializeNew, ExpectedUID: uint32(os.Getuid()), ToolVersion: "test", BuildVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	exec := func(q string) {
		t.Helper()
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO effective_authorization_principals VALUES('principal.reader','human','active',1,'now','now')`)
	exec(`INSERT INTO effective_authorization_grants VALUES('host-read','principal.reader','infrastructure-admin','read','host.read','host','host-a',NULL,1,'active','now','now')`)
	declarations, err := change.NewService(store.NewDeclarationRepository(authority), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	repo := store.NewPlanRepository(authority)
	observations, err := planengine.NewStateObservationReader(repo)
	if err != nil {
		t.Fatal(err)
	}
	plans, err := planengine.NewService(planengine.Config{Repository: repo, Observations: observations, Clock: time.Now, PolicyVersion: "1.0.0", ToolVersion: "1.0.0", ContractVersion: "1.0.0", Risk: "infrastructure", AuthorizationBranch: "human", ExecutorMode: "central", OperationExecutorID: "executor-central"})
	if err != nil {
		t.Fatal(err)
	}
	var count atomic.Int64
	factory := result.NewFactory(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}, func() (string, error) { return fmt.Sprintf("browser-host-%d", count.Add(1)), nil })
	app, err := api.NewApplication(api.Config{Authority: authority, Authorizer: store.NewReadAuthorizer(authority), Reads: store.NewReadRepository(authority), Results: factory})
	if err != nil {
		t.Fatal(err)
	}
	policy := store.NewEffectiveAuthorizationRepository(authority)
	if err = api.RegisterDeclarationPlanOperations(app, api.DeclarationPlanConfig{Declarations: declarations, Plans: plans, Results: factory, Authorization: api.EffectiveAuthorizationConfig{Authorizer: authorization.NewEvaluator(policy), Recorder: policy, Clock: time.Now}}); err != nil {
		t.Fatal(err)
	}
	if err = api.RegisterHostAdoptionOperations(app, api.HostAdoptionOperations{Hosts: store.NewHostAdoptionRepository(authority), Declarations: declarations, Results: factory}); err != nil {
		t.Fatal(err)
	}
	if err = api.RegisterHostReplacementOperations(app, api.HostReplacementOperations{Replacements: store.NewHostReplacementRepository(authority), Declarations: declarations, Results: factory}); err != nil {
		t.Fatal(err)
	}
	auth, _, sessions := newBrowserAuthFixture(t)
	browser, err := NewBrowserHandler(app, http.NotFoundHandler(), auth)
	if err != nil {
		t.Fatal(err)
	}
	request := func(host string) int {
		t.Helper()
		req := httptest.NewRequest("GET", "https://console.example/api/v1/hosts/"+host, nil)
		req.Header.Set("Origin", "https://console.example")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("Sec-Fetch-Mode", "cors")
		req.Header.Set("Sec-Fetch-Dest", "empty")
		req.Header.Set("Cf-Access-Jwt-Assertion", "verified-provider-assertion")
		req.AddCookie(&http.Cookie{Name: BrowserSessionCookieName, Value: sessions.raw})
		response := httptest.NewRecorder()
		browser.ServeHTTP(response, req)
		t.Logf("host=%s status=%d body=%s", host, response.Code, response.Body.String())
		return response.Code
	}
	if got := request("host-a"); got != 404 {
		t.Fatalf("current exact grant should reach missing-host lookup: %d", got)
	}
	if got := request("private-other-host"); got != 403 {
		t.Fatalf("cross-host grant leaked lookup: %d", got)
	}
	// Exercise the actual browser route allowlist before any body or scoped draft
	// preparation. A missing body is rejected by the typed handler, never 404.
	replacement := httptest.NewRequest("POST", "https://console.example/api/v1/host-replacements", nil)
	replacement.Header.Set("Origin", "https://console.example")
	replacement.Header.Set("Sec-Fetch-Site", "same-origin")
	replacement.Header.Set("Sec-Fetch-Mode", "cors")
	replacement.Header.Set("Sec-Fetch-Dest", "empty")
	replacement.Header.Set("Cf-Access-Jwt-Assertion", "verified-provider-assertion")
	replacement.AddCookie(&http.Cookie{Name: BrowserSessionCookieName, Value: sessions.raw})
	response := httptest.NewRecorder()
	browser.ServeHTTP(response, replacement)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("replacement browser route: %d %s", response.Code, response.Body.String())
	}
	exec(`UPDATE effective_authorization_grants SET status='revoked' WHERE grant_id='host-read'`)
	if got := request("host-a"); got != 403 {
		t.Fatalf("revoked current grant accepted: %d", got)
	}
}
