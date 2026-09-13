package server

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/vegastack/vegastack-labs/internal/consoleassets"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

func testConsoleHandler(t *testing.T) http.Handler {
	t.Helper()
	files := fstest.MapFS{
		"index.html":                           {Data: []byte("<!doctype html><title>Console</title>")},
		"nodes.html":                           {Data: []byte("<!doctype html><title>Nodes</title>")},
		"_next/static/app-0123456789.js":       {Data: []byte("export{}")},
		"_next/static/build/_buildManifest.js": {Data: []byte("manifest")},
		"nodes/__next.nodes.__PAGE__.txt":      {Data: []byte("flight")},
	}
	manifest := consoleassets.Manifest{SchemaVersion: 1, BuildDigest: strings.Repeat("a", 64), ContentSecurityPolicy: "default-src 'self'; frame-ancestors 'none'", Files: map[string]consoleassets.Asset{
		"index.html":                           {SHA256: strings.Repeat("1", 64), Size: 37, ContentType: "text/html; charset=utf-8"},
		"nodes.html":                           {SHA256: strings.Repeat("2", 64), Size: 35, ContentType: "text/html; charset=utf-8"},
		"_next/static/app-0123456789.js":       {SHA256: strings.Repeat("3", 64), Size: 8, ContentType: "text/javascript; charset=utf-8", Immutable: true},
		"_next/static/build/_buildManifest.js": {SHA256: strings.Repeat("5", 64), Size: 8, ContentType: "text/javascript; charset=utf-8"},
		"nodes/__next.nodes.__PAGE__.txt":      {SHA256: strings.Repeat("4", 64), Size: 6, ContentType: "text/plain; charset=utf-8"},
	}}
	handler, err := NewConsoleHandler(files, manifest)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func TestConsoleHandlerServesOnlyManifestRoutesWithSecurityHeaders(t *testing.T) {
	handler := testConsoleHandler(t)
	for _, test := range []struct {
		path, contentType, cache string
	}{
		{"/", "text/html; charset=utf-8", "no-store"},
		{"/nodes", "text/html; charset=utf-8", "no-store"},
		{"/_next/static/app-0123456789.js", "text/javascript; charset=utf-8", "public, max-age=31536000, immutable"},
		{"/_next/static/build/_buildManifest.js", "text/javascript; charset=utf-8", "no-store"},
		{"/nodes/__next.nodes.__PAGE__.txt", "text/plain; charset=utf-8", "no-store"},
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://console.example"+test.path, nil))
		if response.Code != http.StatusOK || response.Header().Get("Content-Type") != test.contentType || response.Header().Get("Cache-Control") != test.cache {
			t.Fatalf("%s response = %d %q %q", test.path, response.Code, response.Header().Get("Content-Type"), response.Header().Get("Cache-Control"))
		}
		for _, name := range []string{"Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy"} {
			if response.Header().Get(name) == "" {
				t.Fatalf("%s missing %s", test.path, name)
			}
		}
	}
}

func TestConsoleHandlerRejectsUnknownTraversalDirectoryAndMethods(t *testing.T) {
	handler := testConsoleHandler(t)
	for _, test := range []struct {
		method, target string
		want           int
	}{
		{http.MethodGet, "/missing", http.StatusNotFound},
		{http.MethodGet, "/nodes/", http.StatusOK},
		{http.MethodGet, "/_next/static/", http.StatusNotFound},
		{http.MethodPost, "/", http.StatusMethodNotAllowed},
		{http.MethodGet, "/%2e%2e/index.html", http.StatusBadRequest},
		{http.MethodGet, "/%252e%252e/index.html", http.StatusBadRequest},
		{http.MethodGet, "/nodes%5cprivate", http.StatusBadRequest},
	} {
		request := httptest.NewRequest(test.method, "https://console.example"+test.target, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != test.want {
			t.Fatalf("%s %s status = %d", test.method, test.target, response.Code)
		}
	}
}

func TestBrowserRouterNeverFallsBackFromAPIToConsole(t *testing.T) {
	authenticator, _, sessions := newBrowserAuthFixture(t)
	api := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Error(writer, "API_NOT_FOUND", http.StatusNotFound)
	})
	handler, err := NewBrowserHandler(api, testConsoleHandler(t), authenticator)
	if err != nil {
		t.Fatal(err)
	}
	request := authorizedBrowserRequest(t, http.MethodGet, "/api/v1/not-a-route", sessions.raw)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound || strings.Contains(response.Body.String(), "<title>Console") {
		t.Fatalf("API path used Console fallback: %d %s", response.Code, response.Body.String())
	}
}

func TestBrowserRouterRejectsLocalMutationRoutesBeforeDispatch(t *testing.T) {
	apiCalls := 0
	authenticator, _, sessions := newBrowserAuthFixture(t)
	handler, err := NewBrowserHandler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { apiCalls++ }), testConsoleHandler(t), authenticator)
	if err != nil {
		t.Fatal(err)
	}
	request := authorizedBrowserRequest(t, http.MethodPost, "/api/v1/inventory-drafts/import", sessions.raw)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound || apiCalls != 0 {
		t.Fatalf("remote mutation response = %d, API calls = %d", response.Code, apiCalls)
	}
}

func TestBrowserRouterDispatchesOnlyGeneratedExecutorRoutesWithMachineIdentity(t *testing.T) {
	authenticator, _, sessions := newBrowserAuthFixture(t)
	sessions.principal = identity.Principal{ID: "principal.executor", Method: identity.CloudflareAccessMethod, Kind: identity.PrincipalPolicy}
	apiCalls := 0
	handler, err := NewBrowserHandler(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		principal, ok := identity.PrincipalFromContext(request.Context())
		if !ok || principal != sessions.principal {
			t.Fatalf("machine principal = %#v, %t", principal, ok)
		}
		apiCalls++
		writer.WriteHeader(http.StatusNoContent)
	}), testConsoleHandler(t), authenticator)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://console.example/api/v1/executor-leases/claim", strings.NewReader(`{}`))
	request.Host = "console.example"
	request.Header.Set("Cf-Access-Jwt-Assertion", "verified-provider-assertion")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || apiCalls != 1 || sessions.validates.Load() != 0 {
		t.Fatalf("machine route status/calls/session-validates = %d/%d/%d", response.Code, apiCalls, sessions.validates.Load())
	}

	request = httptest.NewRequest(http.MethodPost, "https://console.example/api/v1/plans/plan-test/execute", strings.NewReader(`{}`))
	request.Host = "console.example"
	request.Header.Set("Cf-Access-Jwt-Assertion", "verified-provider-assertion")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || apiCalls != 1 {
		t.Fatalf("non-executor remote write status/calls = %d/%d", response.Code, apiCalls)
	}
}

func TestBrowserRouterAuthenticatesBeforeRejectingLocalMutationRoutes(t *testing.T) {
	apiCalls := 0
	authenticator, _, _ := newBrowserAuthFixture(t)
	handler, err := NewBrowserHandler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { apiCalls++ }), testConsoleHandler(t), authenticator)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://console.example/api/v1/inventory-drafts/import", strings.NewReader(`{"requestVersion":"1.0.0"}`))
	request.Host = "console.example"
	request.Header.Set("Origin", "https://console.example")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || apiCalls != 0 {
		t.Fatalf("unauthenticated mutation response/calls = %d/%d", response.Code, apiCalls)
	}
}

type sessionProbeApplication struct {
	testApplication
	called bool
}

func (application *sessionProbeApplication) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	_, remote := identity.RemoteIdentityFromContext(request.Context())
	_, principal := identity.PrincipalFromContext(request.Context())
	if !remote || principal {
		http.Error(writer, "missing remote bootstrap identity", http.StatusUnauthorized)
		return
	}
	application.called = true
	writer.WriteHeader(http.StatusNoContent)
}

func TestBrowserRouterAllowsSessionBootstrapThroughService(t *testing.T) {
	authenticator, _, _ := newBrowserAuthFixture(t)
	application := &sessionProbeApplication{}
	service := &service{config: Config{Application: application, Results: testResultFactory()}, state: StateReady}
	handler, err := NewBrowserHandler(service, testConsoleHandler(t), authenticator)
	if err != nil {
		t.Fatal(err)
	}
	request := authorizedBrowserRequest(t, http.MethodPost, "/api/v1/session", "")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || !application.called {
		t.Fatalf("session bootstrap = %d, called %t", response.Code, application.called)
	}
}

func TestBrowserRouterAllowsVerifiedNavigationWithoutLocalSession(t *testing.T) {
	authenticator, adapter, sessions := newBrowserAuthFixture(t)
	handler, err := NewBrowserHandler(http.NotFoundHandler(), testConsoleHandler(t), authenticator)
	if err != nil {
		t.Fatal(err)
	}
	request := authorizedBrowserRequest(t, http.MethodGet, "/", "")
	request.Header.Set("Sec-Fetch-Site", "none")
	request.Header.Set("Sec-Fetch-Mode", "navigate")
	request.Header.Set("Sec-Fetch-Dest", "document")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || adapter.calls.Load() != 1 || sessions.validates.Load() != 0 {
		t.Fatalf("navigation status/calls = %d/%d/%d", response.Code, adapter.calls.Load(), sessions.validates.Load())
	}
}

func TestBrowserAssetAdmissionRejectsCrossSiteAndForgedForwarding(t *testing.T) {
	for _, mutate := range []func(*http.Request){
		func(request *http.Request) { request.Header.Set("Sec-Fetch-Site", "cross-site") },
		func(request *http.Request) {
			request.Host = "internal.example"
			request.Header.Set("X-Forwarded-Host", "console.example")
		},
		func(request *http.Request) { request.TLS = nil; request.Header.Set("X-Forwarded-Proto", "https") },
	} {
		authenticator, _, _ := newBrowserAuthFixture(t)
		handler, err := NewBrowserHandler(http.NotFoundHandler(), testConsoleHandler(t), authenticator)
		if err != nil {
			t.Fatal(err)
		}
		request := authorizedBrowserRequest(t, http.MethodGet, "/", "")
		request.Header.Set("Sec-Fetch-Site", "same-origin")
		request.Header.Set("Sec-Fetch-Mode", "navigate")
		request.Header.Set("Sec-Fetch-Dest", "document")
		mutate(request)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("forged asset request status = %d", response.Code)
		}
	}
}

func authorizedBrowserRequest(t *testing.T, method, target, session string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(method, "https://console.example"+target, nil)
	request.Host = "console.example"
	request.Header.Set("Origin", "https://console.example")
	request.Header.Set("Cf-Access-Jwt-Assertion", "verified-provider-assertion")
	if session != "" {
		request.AddCookie(&http.Cookie{Name: BrowserSessionCookieName, Value: session})
	}
	return request
}

var _ fs.FS = fstest.MapFS{}
