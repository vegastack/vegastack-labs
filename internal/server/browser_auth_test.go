package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type browserIdentityAdapter struct {
	verified identity.VerifiedIdentity
	calls    atomic.Int32
}

func (adapter *browserIdentityAdapter) Verify(context.Context, string) (identity.VerifiedIdentity, error) {
	adapter.calls.Add(1)
	return adapter.verified, nil
}

type browserSessionStore struct {
	principal identity.Principal
	session   store.BrowserSession
	raw       string
	validates atomic.Int32
	creates   atomic.Int32
	renews    atomic.Int32
	logouts   atomic.Int32
}

func (sessions *browserSessionStore) ResolveRemoteIdentity(context.Context, string) (identity.Principal, error) {
	return sessions.principal, nil
}
func (sessions *browserSessionStore) CreateBrowserSession(context.Context, store.BrowserSessionCreate) (store.BrowserSession, string, error) {
	sessions.creates.Add(1)
	return sessions.session, sessions.raw, nil
}
func (sessions *browserSessionStore) ValidateAndTouchBrowserSession(context.Context, string, string, time.Time) (store.BrowserSession, error) {
	sessions.validates.Add(1)
	return sessions.session, nil
}
func (sessions *browserSessionStore) RenewBrowserSession(context.Context, string, string, time.Time) (store.BrowserSession, string, error) {
	sessions.renews.Add(1)
	return sessions.session, sessions.raw + "-renewed", nil
}
func (sessions *browserSessionStore) LogoutBrowserSession(context.Context, string, string) error {
	sessions.logouts.Add(1)
	return nil
}

func newBrowserAuthFixture(t *testing.T) (*BrowserAuthenticator, *browserIdentityAdapter, *browserSessionStore) {
	t.Helper()
	now := time.Date(2026, 9, 10, 9, 0, 0, 0, time.UTC)
	verified := identity.VerifiedIdentity{Issuer: "https://access.example", Subject: "subject", Audiences: []string{"aud-console"}, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Method: identity.CloudflareAccessMethod}
	adapter := &browserIdentityAdapter{verified: verified}
	binding, err := identity.BindingDigest(verified)
	if err != nil {
		t.Fatal(err)
	}
	sessions := &browserSessionStore{
		principal: identity.Principal{ID: "principal.reader", Method: identity.CloudflareAccessMethod},
		raw:       strings.Repeat("a", 43),
		session: store.BrowserSession{BindingDigest: binding, PrincipalID: "principal.reader", Status: store.BrowserSessionActive,
			IssuedAt: now, LastSeenAt: now, IdleExpiresAt: now.Add(15 * time.Minute), AbsoluteExpiresAt: now.Add(8 * time.Hour), ExternalExpiresAt: now.Add(time.Hour)},
	}
	authenticator, err := NewBrowserAuthenticator(BrowserAuthConfig{ExactOrigin: "https://console.example", ExactHost: "console.example", Identities: adapter, Sessions: sessions, Results: testResultFactory()})
	if err != nil {
		t.Fatal(err)
	}
	return authenticator, adapter, sessions
}

func TestBrowserAuthenticatorOrdersOriginJWTSessionAndPrincipal(t *testing.T) {
	authenticator, adapter, sessions := newBrowserAuthFixture(t)
	downstreamCalls := atomic.Int32{}
	downstream := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		downstreamCalls.Add(1)
		principal, ok := identity.PrincipalFromContext(request.Context())
		if !ok || principal.ID != "principal.reader" || principal.Method != identity.CloudflareAccessMethod {
			t.Fatalf("principal = %#v, %t", principal, ok)
		}
		writer.WriteHeader(http.StatusNoContent)
	})
	request := httptest.NewRequest(http.MethodGet, "https://console.example/api/v1/summary?unknown=private-canary", nil)
	request.Host = "console.example"
	request.Header.Set("Origin", "https://console.example")
	request.Header.Set("Cf-Access-Jwt-Assertion", "verified-provider-assertion")
	request.AddCookie(&http.Cookie{Name: BrowserSessionCookieName, Value: sessions.raw})
	response := httptest.NewRecorder()
	authenticator.Wrap(downstream).ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || downstreamCalls.Load() != 1 || adapter.calls.Load() != 1 || sessions.validates.Load() != 1 {
		t.Fatalf("status/calls = %d/%d/%d/%d", response.Code, downstreamCalls.Load(), adapter.calls.Load(), sessions.validates.Load())
	}
}

func TestBrowserAuthenticatorFailsClosedBeforeDownstreamParsing(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*http.Request, *browserSessionStore)
	}{
		{name: "missing origin", mutate: func(request *http.Request, _ *browserSessionStore) { request.Header.Del("Origin") }},
		{name: "wrong origin", mutate: func(request *http.Request, _ *browserSessionStore) {
			request.Header.Set("Origin", "https://evil.example")
		}},
		{name: "wrong host", mutate: func(request *http.Request, _ *browserSessionStore) { request.Host = "origin.internal" }},
		{name: "email only", mutate: func(request *http.Request, _ *browserSessionStore) {
			request.Header.Del("Cf-Access-Jwt-Assertion")
			request.Header.Set("Cf-Access-Authenticated-User-Email", "private@example.test")
		}},
		{name: "duplicate assertion", mutate: func(request *http.Request, _ *browserSessionStore) {
			request.Header.Add("Cf-Access-Jwt-Assertion", "second")
		}},
		{name: "missing session", mutate: func(request *http.Request, _ *browserSessionStore) { request.Header.Del("Cookie") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			authenticator, _, sessions := newBrowserAuthFixture(t)
			request := httptest.NewRequest(http.MethodGet, "https://console.example/api/v1/summary?malformed=private-canary", nil)
			request.Host = "console.example"
			request.Header.Set("Origin", "https://console.example")
			request.Header.Set("Cf-Access-Jwt-Assertion", "verified-provider-assertion")
			request.AddCookie(&http.Cookie{Name: BrowserSessionCookieName, Value: sessions.raw})
			test.mutate(request, sessions)
			called := false
			response := httptest.NewRecorder()
			authenticator.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })).ServeHTTP(response, request)
			if response.Code != http.StatusUnauthorized || called || strings.Contains(response.Body.String(), "private-canary") || strings.Contains(response.Body.String(), "private@example") {
				t.Fatalf("response = %d called=%t body=%s", response.Code, called, response.Body.String())
			}
		})
	}
}

func TestBrowserSessionManagerCreatesRenewsAndLocallyLogsOutWithSecureCookies(t *testing.T) {
	authenticator, _, sessions := newBrowserAuthFixture(t)
	manager := authenticator.SessionService()
	verified := identity.VerifiedIdentity{Issuer: "https://access.example", Subject: "subject", Audiences: []string{"aud-console"}, IssuedAt: sessions.session.IssuedAt.Add(-time.Minute), ExpiresAt: sessions.session.ExternalExpiresAt, Method: identity.CloudflareAccessMethod}
	ctx, err := identity.WithVerifiedRemoteIdentity(context.Background(), verified)
	if err != nil {
		t.Fatal(err)
	}
	created, err := manager.Create(ctx)
	if err != nil || created.Cookie == nil || !created.Cookie.Secure || !created.Cookie.HttpOnly || created.Cookie.SameSite != http.SameSiteStrictMode || created.Cookie.Path != "/" || created.Cookie.Value != sessions.raw {
		t.Fatalf("create = %#v, %v", created, err)
	}
	ctx = withBrowserSessionContext(ctx, sessions.raw, sessions.session)
	renewed, err := manager.Renew(ctx)
	if err != nil || renewed.Cookie.Value != sessions.raw+"-renewed" {
		t.Fatalf("renew = %#v, %v", renewed, err)
	}
	loggedOut, err := manager.Logout(ctx)
	if err != nil || loggedOut.Cookie.MaxAge != -1 || loggedOut.Data.LogoutScope != "vsk-labs-session-only" || sessions.logouts.Load() != 1 {
		t.Fatalf("logout = %#v, %v", loggedOut, err)
	}
}

func TestBrowserAuthDoesNotAffectIndependentLocalPrincipalContext(t *testing.T) {
	principal := identity.Principal{ID: "principal.local", Method: identity.LocalOSPeerMethod}
	ctx := identity.WithVerifiedPrincipal(context.Background(), principal)
	got, ok := identity.PrincipalFromContext(ctx)
	if !ok || got != principal {
		t.Fatalf("local recovery principal = %#v, %t", got, ok)
	}
}

var _ store.BrowserSessionStore = (*browserSessionStore)(nil)
var _ = generated.ErrorCodeAuthenticationRequired
