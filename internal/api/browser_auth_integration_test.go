package api_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/inventory"
	"github.com/vegastack/vegastack-labs/internal/readmodel"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/server"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type integrationAuthority struct{}

func (integrationAuthority) Health(context.Context) (store.Health, error) {
	return store.Health{Mode: store.DatabaseReady, Revision: store.RevisionToken{StateRevision: 7, RecoveryEpoch: 2}}, nil
}
func (integrationAuthority) Close() error { return nil }

type integrationIdentityAdapter struct{ value identity.VerifiedIdentity }

func (adapter integrationIdentityAdapter) Verify(context.Context, string) (identity.VerifiedIdentity, error) {
	return adapter.value, nil
}

type integrationSessions struct {
	session   store.BrowserSession
	principal identity.Principal
	raw       string
}

func (sessions integrationSessions) ResolveRemoteIdentity(context.Context, string) (identity.Principal, error) {
	return sessions.principal, nil
}
func (sessions integrationSessions) CreateBrowserSession(context.Context, store.BrowserSessionCreate) (store.BrowserSession, string, error) {
	return sessions.session, sessions.raw, nil
}
func (sessions integrationSessions) ValidateAndTouchBrowserSession(context.Context, string, string, time.Time) (store.BrowserSession, error) {
	return sessions.session, nil
}
func (sessions integrationSessions) RenewBrowserSession(context.Context, string, string, time.Time) (store.BrowserSession, string, error) {
	return sessions.session, sessions.raw, nil
}
func (sessions integrationSessions) LogoutBrowserSession(context.Context, string, string) error {
	return nil
}

type integrationAuthorizer struct{}

func (authorizer integrationAuthorizer) AuthorizeRead(_ context.Context, principal identity.Principal, target authorization.ReadTarget) (authorization.ReadScope, error) {
	if principal.ID != "principal.remote" || principal.Method != identity.CloudflareAccessMethod || target.Capability != "platform.summary.read" || target.ResourceKind != "platform-summary" {
		return authorization.ReadScope{}, failure.New(generated.ErrorCodeAuthorizationDenied, "read-scope", false)
	}
	return authorization.ReadScope{PrincipalID: principal.ID, Capability: target.Capability, ResourceKind: target.ResourceKind, GrantRevision: 1, ScopeDigest: "sha256:" + strings.Repeat("a", 64)}, nil
}

type integrationReads struct{}

func (reads integrationReads) CurrentRevision(context.Context, authorization.ReadScope) (store.RevisionToken, error) {
	return store.RevisionToken{StateRevision: 7, RecoveryEpoch: 2}, nil
}
func (reads integrationReads) DatabaseStatus(context.Context, authorization.ReadScope) (readmodel.DatabaseStatus, error) {
	return readmodel.DatabaseStatus{}, nil
}
func (reads integrationReads) Summary(context.Context, authorization.ReadScope) (readmodel.Summary, error) {
	return readmodel.Summary{DatabaseMode: "ready", ReadAvailable: true, MutationAvailable: false, StateRevision: 7, RecoveryEpoch: 2}, nil
}
func (reads integrationReads) ListDrafts(context.Context, authorization.ReadScope, inventory.DraftListQuery, store.RevisionToken) (readmodel.DraftPage, error) {
	return readmodel.DraftPage{}, nil
}
func (reads integrationReads) GetDraft(context.Context, authorization.ReadScope, inventory.DraftRef) (readmodel.Draft, error) {
	return readmodel.Draft{}, nil
}
func (reads integrationReads) ListRecords(context.Context, authorization.ReadScope, inventory.DraftRef, inventory.RecordListQuery, store.RevisionToken) (readmodel.RecordPage, error) {
	return readmodel.RecordPage{}, nil
}
func (reads integrationReads) GetRecord(context.Context, authorization.ReadScope, inventory.DraftRef, string, inventory.LocalID) (readmodel.Record, error) {
	return readmodel.Record{}, nil
}
func (reads integrationReads) ReadEvents(context.Context, authorization.ReadScope, audit.EventID, int) (readmodel.EventBatch, error) {
	return readmodel.EventBatch{}, nil
}
func (reads integrationReads) EventHighWater(context.Context, authorization.ReadScope) (audit.EventID, error) {
	return 0, nil
}
func (reads integrationReads) EventExists(context.Context, authorization.ReadScope, audit.EventID) (bool, error) {
	return false, nil
}

func TestRemoteBrowserMiddlewareReachesAPIResourceAuthorizationBeforeParsing(t *testing.T) {
	now := time.Date(2026, 9, 10, 9, 0, 0, 0, time.UTC)
	verified := identity.VerifiedIdentity{Issuer: "https://access.example", Subject: "subject", Audiences: []string{"aud-console"}, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Method: identity.CloudflareAccessMethod}
	binding, err := identity.BindingDigest(verified)
	if err != nil {
		t.Fatal(err)
	}
	raw := strings.Repeat("A", 43)
	sessions := integrationSessions{principal: identity.Principal{ID: "principal.remote", Method: identity.CloudflareAccessMethod}, raw: raw, session: store.BrowserSession{BindingDigest: binding, PrincipalID: "principal.remote", Status: store.BrowserSessionActive, IssuedAt: now, LastSeenAt: now, IdleExpiresAt: now.Add(15 * time.Minute), AbsoluteExpiresAt: now.Add(8 * time.Hour), ExternalExpiresAt: now.Add(time.Hour)}}
	factory := result.NewFactory(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}, func() (string, error) { return "request-test", nil })
	authenticator, err := server.NewBrowserAuthenticator(server.BrowserAuthConfig{ExactOrigin: "https://console.example", ExactHost: "console.example", Identities: integrationIdentityAdapter{value: verified}, Sessions: sessions, Results: factory})
	if err != nil {
		t.Fatal(err)
	}
	app, err := api.NewApplication(api.Config{Authority: integrationAuthority{}, Authorizer: integrationAuthorizer{}, Reads: integrationReads{}, Results: factory, Sessions: authenticator.SessionService()})
	if err != nil {
		t.Fatal(err)
	}
	host := httptest.NewTLSServer(authenticator.Wrap(app))
	defer host.Close()
	request, err := http.NewRequest(http.MethodGet, host.URL+"/api/v1/summary", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "console.example"
	request.Header.Set("Origin", "https://console.example")
	request.Header.Set("Cf-Access-Jwt-Assertion", "fixture-assertion")
	request.AddCookie(&http.Cookie{Name: server.BrowserSessionCookieName, Value: raw})
	response, err := host.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("allowed summary status = %d", response.StatusCode)
	}

	denied, err := http.NewRequest(http.MethodGet, host.URL+"/api/v1/inventory-drafts/private-canary/revisions/not-a-number", nil)
	if err != nil {
		t.Fatal(err)
	}
	denied.Host = "console.example"
	denied.Header.Set("Origin", "https://console.example")
	denied.Header.Set("Cf-Access-Jwt-Assertion", "fixture-assertion")
	denied.AddCookie(&http.Cookie{Name: server.BrowserSessionCookieName, Value: raw})
	deniedResponse, err := host.Client().Do(denied)
	if err != nil {
		t.Fatal(err)
	}
	defer deniedResponse.Body.Close()
	deniedBody := new(strings.Builder)
	if _, err := io.Copy(deniedBody, deniedResponse.Body); err != nil {
		t.Fatal(err)
	}
	if deniedResponse.StatusCode != http.StatusForbidden || strings.Contains(deniedBody.String(), "private-canary") || strings.Contains(deniedBody.String(), "not-a-number") {
		t.Fatalf("denied response = %d %s", deniedResponse.StatusCode, deniedBody.String())
	}
}

var _ store.BrowserSessionStore = integrationSessions{}
var _ api.ReadRepository = integrationReads{}
