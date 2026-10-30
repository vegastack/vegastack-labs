package server

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/store"
)

const BrowserSessionCookieName = "vsk_labs_session"

type BrowserAuthConfig struct {
	ExactOrigin string
	ExactHost   string
	Identities  identity.VerifiedIdentityAdapter
	Sessions    store.BrowserSessionStore
	Results     *result.Factory
}

type BrowserAuthenticator struct {
	config  BrowserAuthConfig
	manager *browserSessionManager
}

type browserSessionContextKey struct{}
type browserSessionContextValue struct {
	raw     string
	session store.BrowserSession
}

type browserDenialAuditor interface {
	AuditBrowserSessionDenial(context.Context, identity.Principal, string) error
}

func NewBrowserAuthenticator(config BrowserAuthConfig) (*BrowserAuthenticator, error) {
	origin, err := url.Parse(config.ExactOrigin)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || (origin.Path != "" && origin.Path != "/") || config.ExactHost == "" || origin.Host != config.ExactHost || config.Identities == nil || config.Sessions == nil || config.Results == nil {
		return nil, failure.New(generated.ErrorCodeInputInvalid, "browser-auth-config", false)
	}
	manager := &browserSessionManager{sessions: config.Sessions}
	return &BrowserAuthenticator{config: config, manager: manager}, nil
}

func (authenticator *BrowserAuthenticator) SessionService() api.BrowserSessionService {
	return authenticator.manager
}

// Start primes adapters that own refreshable verification material. A remote
// listener must call this before accepting requests; refresh failure prevents
// remote admission and never affects the independent local Unix listener.
func (authenticator *BrowserAuthenticator) Start(ctx context.Context) error {
	refresher, ok := authenticator.config.Identities.(interface{ Refresh(context.Context) error })
	if !ok {
		return nil
	}
	return refresher.Refresh(ctx)
}

func (authenticator *BrowserAuthenticator) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if next == nil || !authenticator.browserOriginAllowed(request) {
			logBrowserAuthReason("api-origin-or-fetch-metadata")
			authenticator.writeFailure(writer, generated.ErrorCodeAuthenticationRequired)
			return
		}
		ctx, verified, bindingDigest, ok := authenticator.verifyExternalRequest(request)
		if !ok {
			authenticator.writeFailure(writer, generated.ErrorCodeAuthenticationRequired)
			return
		}
		if request.URL.Path == "/api/v1/session" {
			next.ServeHTTP(writer, request.WithContext(ctx))
			return
		}
		raw, ok := exactSessionCookie(request)
		if !ok {
			logBrowserAuthReason("session-cookie-missing")
			authenticator.auditSessionDenial(ctx, bindingDigest)
			authenticator.writeFailure(writer, generated.ErrorCodeAuthenticationRequired)
			return
		}
		session, err := authenticator.config.Sessions.ValidateAndTouchBrowserSession(ctx, raw, bindingDigest, verified.ExpiresAt)
		if err != nil {
			logBrowserAuthReason("session-invalid")
			authenticator.auditSessionDenial(ctx, bindingDigest)
			authenticator.writeFailure(writer, generated.ErrorCodeAuthenticationRequired)
			return
		}
		principal := identity.Principal{ID: session.PrincipalID, Method: identity.CloudflareAccessMethod}
		ctx = identity.WithVerifiedPrincipal(ctx, principal)
		ctx = withBrowserSessionContext(ctx, raw, session)
		next.ServeHTTP(writer, request.WithContext(ctx))
	})
}

// WrapAssets admits only safe browser navigation/subresource requests carrying
// a verified external identity. Static bytes contain no operational data; API
// requests continue through Wrap and require the local revocable session.
func (authenticator *BrowserAuthenticator) WrapAssets(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if next == nil || !authenticator.browserAssetRequestAllowed(request) {
			logBrowserAuthReason("asset-fetch-metadata")
			authenticator.writeFailure(writer, generated.ErrorCodeAuthenticationRequired)
			return
		}
		ctx, verified, bindingDigest, ok := authenticator.verifyExternalRequest(request)
		if !ok {
			authenticator.writeFailure(writer, generated.ErrorCodeAuthenticationRequired)
			return
		}
		authenticator.bootstrapSession(writer, request, ctx, verified, bindingDigest)
		next.ServeHTTP(writer, request.WithContext(ctx))
	})
}

func (authenticator *BrowserAuthenticator) verifyExternalRequest(request *http.Request) (context.Context, identity.VerifiedIdentity, string, bool) {
	if request.TLS == nil || request.Host != authenticator.config.ExactHost {
		logBrowserAuthReason("tls-or-host")
		return nil, identity.VerifiedIdentity{}, "", false
	}
	assertions := request.Header.Values("Cf-Access-Jwt-Assertion")
	if len(assertions) != 1 || assertions[0] == "" || strings.Contains(assertions[0], ",") {
		logBrowserAuthReason("assertion-header")
		return nil, identity.VerifiedIdentity{}, "", false
	}
	verified, err := authenticator.config.Identities.Verify(request.Context(), assertions[0])
	if err != nil {
		if stable, ok := failure.As(err); ok {
			logBrowserAuthReason("assertion-verify:" + stable.Code + ":" + stable.Target)
		} else {
			logBrowserAuthReason(fmt.Sprintf("assertion-verify:unclassified:%T", err))
		}
		return nil, identity.VerifiedIdentity{}, "", false
	}
	bindingDigest, err := identity.BindingDigest(verified)
	if err != nil {
		logBrowserAuthReason("binding-digest")
		return nil, identity.VerifiedIdentity{}, "", false
	}
	ctx, err := identity.WithVerifiedRemoteIdentity(request.Context(), verified)
	if err != nil {
		logBrowserAuthReason("remote-identity")
		return nil, identity.VerifiedIdentity{}, "", false
	}
	return ctx, verified, bindingDigest, true
}

func (authenticator *BrowserAuthenticator) browserOriginAllowed(request *http.Request) bool {
	origins := request.Header.Values("Origin")
	if len(origins) > 1 || (len(origins) == 1 && origins[0] != authenticator.config.ExactOrigin) {
		return false
	}
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		return len(origins) == 1
	}
	if len(origins) == 1 {
		return true
	}
	return exactHeaderValue(request, "Sec-Fetch-Site", "same-origin") &&
		exactHeaderValue(request, "Sec-Fetch-Mode", "cors") &&
		exactHeaderValue(request, "Sec-Fetch-Dest", "empty")
}

func (authenticator *BrowserAuthenticator) browserAssetRequestAllowed(request *http.Request) bool {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		return false
	}
	origins := request.Header.Values("Origin")
	if len(origins) > 1 || (len(origins) == 1 && origins[0] != authenticator.config.ExactOrigin) {
		return false
	}
	site := request.Header.Values("Sec-Fetch-Site")
	mode := request.Header.Values("Sec-Fetch-Mode")
	destination := request.Header.Values("Sec-Fetch-Dest")
	if len(site) != 1 || len(mode) != 1 || len(destination) != 1 {
		return false
	}
	if mode[0] == "navigate" && destination[0] == "document" {
		return site[0] == "none" || site[0] == "same-origin"
	}
	if site[0] != "same-origin" {
		return false
	}
	// Cross-origin-enabled subresources send Origin. Require the exact configured
	// origin before admitting their provider assertion; no-cors assets rely on
	// the exact same-origin Fetch Metadata tuple instead.
	if mode[0] == "cors" && destination[0] != "empty" && len(origins) != 1 {
		return false
	}
	if mode[0] != "cors" && mode[0] != "no-cors" {
		return false
	}
	switch destination[0] {
	case "font", "image", "script", "style", "empty":
		return true
	default:
		return false
	}
}

func exactHeaderValue(request *http.Request, name, expected string) bool {
	values := request.Header.Values(name)
	return len(values) == 1 && values[0] == expected
}

func (authenticator *BrowserAuthenticator) auditSessionDenial(ctx context.Context, bindingDigest string) {
	auditor, ok := authenticator.config.Sessions.(browserDenialAuditor)
	if !ok {
		return
	}
	principal, err := authenticator.config.Sessions.ResolveRemoteIdentity(ctx, bindingDigest)
	if err != nil {
		return
	}
	_ = auditor.AuditBrowserSessionDenial(ctx, principal, "session-invalid")
}

func exactSessionCookie(request *http.Request) (string, bool) {
	var value string
	count := 0
	for _, cookie := range request.Cookies() {
		if cookie.Name == BrowserSessionCookieName {
			count++
			value = cookie.Value
		}
	}
	if count != 1 {
		return "", false
	}
	if _, err := store.BrowserSessionDigest(value); err != nil {
		return "", false
	}
	return value, true
}

func withBrowserSessionContext(ctx context.Context, raw string, session store.BrowserSession) context.Context {
	return context.WithValue(ctx, browserSessionContextKey{}, browserSessionContextValue{raw: raw, session: session})
}

func browserSessionFromContext(ctx context.Context) (browserSessionContextValue, bool) {
	value, ok := ctx.Value(browserSessionContextKey{}).(browserSessionContextValue)
	return value, ok && value.raw != "" && value.session.PrincipalID != ""
}

func (authenticator *BrowserAuthenticator) writeFailure(writer http.ResponseWriter, code string) {
	envelope, err := authenticator.config.Results.Failure("api.browser-auth", generated.RunStatusFailed, code, "browser-auth", false, 0, 0, struct{}{})
	if err != nil {
		http.Error(writer, generated.ErrorCodeIntegrityFailure, http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusUnauthorized)
	_ = result.Encode(writer, envelope)
}

type browserSessionManager struct{ sessions store.BrowserSessionStore }

func (manager *browserSessionManager) Create(ctx context.Context) (api.BrowserSessionResult, error) {
	verified, ok := identity.RemoteIdentityFromContext(ctx)
	if !ok {
		return api.BrowserSessionResult{}, failure.New(generated.ErrorCodeAuthenticationRequired, "browser-session", false)
	}
	binding, err := identity.BindingDigest(verified)
	if err != nil {
		return api.BrowserSessionResult{}, failure.New(generated.ErrorCodeAuthenticationRequired, "browser-session", false)
	}
	principal, err := manager.sessions.ResolveRemoteIdentity(ctx, binding)
	if err != nil {
		logBrowserSessionReason("create:resolve-identity", err)
		return api.BrowserSessionResult{}, asBrowserFailure(err)
	}
	session, raw, err := manager.sessions.CreateBrowserSession(ctx, store.BrowserSessionCreate{Principal: principal, BindingDigest: binding, ExternalExpiresAt: verified.ExpiresAt})
	if err != nil {
		logBrowserSessionReason("create:store", err)
		return api.BrowserSessionResult{}, asBrowserFailure(err)
	}
	return browserSessionResult(session, sessionCookie(raw)), nil
}

func (manager *browserSessionManager) Renew(ctx context.Context) (api.BrowserSessionResult, error) {
	verified, ok := identity.RemoteIdentityFromContext(ctx)
	current, sessionOK := browserSessionFromContext(ctx)
	if !ok || !sessionOK {
		return api.BrowserSessionResult{}, failure.New(generated.ErrorCodeAuthenticationRequired, "browser-session", false)
	}
	binding, err := identity.BindingDigest(verified)
	if err != nil || binding != current.session.BindingDigest {
		return api.BrowserSessionResult{}, failure.New(generated.ErrorCodeAuthenticationRequired, "browser-session", false)
	}
	session, raw, err := manager.sessions.RenewBrowserSession(ctx, current.raw, binding, verified.ExpiresAt)
	if err != nil {
		return api.BrowserSessionResult{}, asBrowserFailure(err)
	}
	return browserSessionResult(session, sessionCookie(raw)), nil
}

func (manager *browserSessionManager) Logout(ctx context.Context) (api.BrowserSessionResult, error) {
	verified, ok := identity.RemoteIdentityFromContext(ctx)
	current, sessionOK := browserSessionFromContext(ctx)
	if !ok || !sessionOK {
		return api.BrowserSessionResult{}, failure.New(generated.ErrorCodeAuthenticationRequired, "browser-session", false)
	}
	binding, err := identity.BindingDigest(verified)
	if err != nil || binding != current.session.BindingDigest {
		return api.BrowserSessionResult{}, failure.New(generated.ErrorCodeAuthenticationRequired, "browser-session", false)
	}
	if err := manager.sessions.LogoutBrowserSession(ctx, current.raw, binding); err != nil {
		return api.BrowserSessionResult{}, asBrowserFailure(err)
	}
	return browserSessionResult(current.session, expiredSessionCookie()), nil
}

func browserSessionResult(session store.BrowserSession, cookie *http.Cookie) api.BrowserSessionResult {
	return api.BrowserSessionResult{Data: generated.ApiBrowserSessionData{
		PrincipalID: session.PrincipalID, IdleExpiresAt: session.IdleExpiresAt.UTC().Format(time.RFC3339Nano),
		AbsoluteExpiresAt: session.AbsoluteExpiresAt.UTC().Format(time.RFC3339Nano), LogoutScope: "vsk-labs-session-only",
	}, Cookie: cookie}
}

func sessionCookie(raw string) *http.Cookie {
	return &http.Cookie{Name: BrowserSessionCookieName, Value: raw, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
}

func expiredSessionCookie() *http.Cookie {
	return &http.Cookie{Name: BrowserSessionCookieName, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1, Expires: time.Unix(1, 0).UTC()}
}

func asBrowserFailure(err error) error {
	if stable, ok := failure.As(err); ok {
		return stable
	}
	if coded, ok := err.(interface{ Code() string }); ok {
		code := coded.Code()
		if _, known := generated.ErrorExitCodes[code]; known {
			return failure.New(code, "browser-session", false)
		}
	}
	return failure.New(generated.ErrorCodeDependencyUnavailable, "browser-session", false)
}

var _ api.BrowserSessionService = (*browserSessionManager)(nil)

// logBrowserAuthReason writes a fixed step name (never headers, tokens or paths) to
// the service log so a browser denial can be diagnosed.
func logBrowserAuthReason(step string) {
	fmt.Fprintf(os.Stderr, "browser-auth denied: step=%s\n", step)
}

// logBrowserSessionReason writes only the step and the stable failure code and target.
func logBrowserSessionReason(step string, err error) {
	code, target := "unclassified", ""
	if stable, ok := failure.As(err); ok {
		code, target = stable.Code, stable.Target
	} else if coded, ok := err.(interface{ Code() string }); ok {
		code = coded.Code()
	}
	fmt.Fprintf(os.Stderr, "browser-session failed: step=%s code=%s target=%s type=%T\n", step, code, target, err)
}

// bootstrapSession gives a verified browser its local, revocable session when it
// opens the Console document. The shipped Console never calls POST /api/v1/session,
// so without this every API read would be unauthenticated. It uses the same verified
// identity and the same session manager as that endpoint, and only runs for a safe
// top-level document navigation that already passed the Fetch Metadata gate.
func (authenticator *BrowserAuthenticator) bootstrapSession(writer http.ResponseWriter, request *http.Request, ctx context.Context, verified identity.VerifiedIdentity, bindingDigest string) {
	if !exactHeaderValue(request, "Sec-Fetch-Mode", "navigate") || !exactHeaderValue(request, "Sec-Fetch-Dest", "document") {
		return
	}
	if raw, ok := exactSessionCookie(request); ok {
		if _, err := authenticator.config.Sessions.ValidateAndTouchBrowserSession(ctx, raw, bindingDigest, verified.ExpiresAt); err == nil {
			return
		}
	}
	created, err := authenticator.manager.Create(ctx)
	if err != nil || created.Cookie == nil {
		logBrowserSessionReason("document-bootstrap", err)
		return
	}
	http.SetCookie(writer, created.Cookie)
}
