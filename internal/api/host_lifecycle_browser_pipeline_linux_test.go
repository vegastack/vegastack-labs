//go:build linux

package api_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/result"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/server"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// Browser sessions, target/discovery/adoption, action/role effects, approvals and
// replacement CAS use production paths. External identity/SSH, credential delivery,
// and native baseline/qualification producer chains are synthetic software
// fixtures; this test provides no native host qualification or live authority.
// Initial alias declaration creation intentionally retains its local-operator
// boundary, with explicit browser rejection before the typed local API call.
func TestHostLifecycleBrowserLinkedReplacementPipeline(t *testing.T) {
	api.RunReplacementBrowserAcceptance(t, func(app *api.Application, authority *store.Store, db *sql.DB, at time.Time) func(string, string, any) *httptest.ResponseRecorder {
		verified := identity.VerifiedIdentity{Issuer: "https://access.example", Subject: "host-lifecycle-human", Audiences: []string{"aud-console"}, IssuedAt: at.Add(-time.Minute), ExpiresAt: at.Add(time.Hour), Method: identity.CloudflareAccessMethod}
		binding, err := identity.BindingDigest(verified)
		if err != nil {
			t.Fatal(err)
		}
		for _, q := range []string{`INSERT OR IGNORE INTO read_principals VALUES('human-a','active',1,'now','now')`} {
			if _, err = db.Exec(q); err != nil {
				t.Fatal(err)
			}
		}
		if _, err = db.Exec(`INSERT OR IGNORE INTO remote_identity_bindings VALUES(?,'human-a','active',?,?)`, binding, at.Format(time.RFC3339), at.Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
		principal := identity.Principal{ID: "human-a", Method: identity.CloudflareAccessMethod, Kind: identity.PrincipalHuman}
		_, raw, err := authority.CreateBrowserSession(context.Background(), store.BrowserSessionCreate{Principal: principal, BindingDigest: binding, ExternalExpiresAt: verified.ExpiresAt})
		if err != nil {
			t.Fatal(err)
		}
		auth, err := server.NewBrowserAuthenticator(server.BrowserAuthConfig{ExactOrigin: "https://console.example", ExactHost: "console.example", Identities: integrationIdentityAdapter{value: verified}, Sessions: authority, Results: result.NewFactory(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}, func() (string, error) { return "browser-auth", nil })})
		if err != nil {
			t.Fatal(err)
		}
		browser, err := server.NewBrowserHandler(app, http.NotFoundHandler(), auth)
		if err != nil {
			t.Fatal(err)
		}
		request := func(method, path string, input any) *httptest.ResponseRecorder {
			t.Helper()
			var body []byte
			if input != nil {
				body, err = json.Marshal(input)
				if err != nil {
					t.Fatal(err)
				}
			}
			req := httptest.NewRequest(method, "https://console.example"+path, bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Origin", "https://console.example")
			req.Header.Set("Sec-Fetch-Site", "same-origin")
			req.Header.Set("Sec-Fetch-Mode", "cors")
			req.Header.Set("Sec-Fetch-Dest", "empty")
			req.Header.Set("Cf-Access-Jwt-Assertion", "verified-provider-assertion")
			req.AddCookie(&http.Cookie{Name: server.BrowserSessionCookieName, Value: raw})
			response := httptest.NewRecorder()
			browser.ServeHTTP(response, req)
			return response
		}
		for _, mode := range []string{"missing-session", "wrong-origin"} {
			req := httptest.NewRequest(http.MethodPost, "https://console.example/api/v1/host-replacements", bytes.NewBufferString("not-json"))
			req.Header.Set("Origin", "https://console.example")
			req.Header.Set("Sec-Fetch-Site", "same-origin")
			req.Header.Set("Sec-Fetch-Mode", "cors")
			req.Header.Set("Sec-Fetch-Dest", "empty")
			req.Header.Set("Cf-Access-Jwt-Assertion", "verified-provider-assertion")
			if mode == "wrong-origin" {
				req.Header.Set("Origin", "https://other.example")
				req.AddCookie(&http.Cookie{Name: server.BrowserSessionCookieName, Value: raw})
			}
			response := httptest.NewRecorder()
			browser.ServeHTTP(response, req)
			if response.Code != http.StatusUnauthorized && response.Code != http.StatusForbidden {
				t.Fatalf("%s: %d %s", mode, response.Code, response.Body.String())
			}
		}
		return request
	}, func(targets *store.HostDiscoveryRepository) runengine.GateVerifier {
		return server.NewDiscoveryConsoleGate(targets, runengine.UnavailableGateVerifier{})
	})
}
