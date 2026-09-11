//go:build linux

package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	_ "github.com/ncruces/go-sqlite3/driver"
	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type browserIntegrationClock struct {
	mu sync.Mutex
	at time.Time
}

func (clock *browserIntegrationClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.at
}

func (clock *browserIntegrationClock) Advance(duration time.Duration) {
	clock.mu.Lock()
	clock.at = clock.at.Add(duration)
	clock.mu.Unlock()
}

func TestRealBrowserStackAndLocalRecoveryRemainIndependent(t *testing.T) {
	clock := &browserIntegrationClock{at: time.Date(2026, 9, 10, 9, 0, 0, 0, time.UTC)}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const keyID = "integration-key"
	var providerAvailable atomic.Bool
	providerAvailable.Store(true)
	keyServer := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !providerAvailable.Load() {
			http.Error(writer, "private provider detail", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(writer).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: keyID, Algorithm: string(jose.RS256), Use: "sig"}}})
	}))
	defer keyServer.Close()
	assertion := signBrowserIntegrationJWT(t, key, keyID, keyServer.URL, clock.Now(), 30*time.Hour)
	verified := identity.VerifiedIdentity{
		Issuer: keyServer.URL, Subject: "subject-real-browser", Audiences: []string{"aud-console"},
		IssuedAt: clock.Now().Add(-time.Minute), ExpiresAt: clock.Now().Add(30 * time.Hour), Method: identity.CloudflareAccessMethod,
	}
	bindingDigest, err := identity.BindingDigest(verified)
	if err != nil {
		t.Fatal(err)
	}

	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(directory, "control.db")
	config := store.Config{DatabasePath: databasePath, Mode: store.InitializeNew, ExpectedUID: uint32(os.Getuid()), ToolVersion: "test", BuildVersion: "test", Clock: clock.Now}
	initial, err := store.Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	if err := initial.Close(); err != nil {
		t.Fatal(err)
	}
	seedBrowserIntegrationAuthority(t, databasePath, bindingDigest, clock.Now())
	config.Mode = store.OpenExisting
	authority, err := store.Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = authority.Close() })

	adapter, err := identity.NewCloudflareAccessAdapter(identity.CloudflareAccessConfig{
		Issuer: keyServer.URL, Audience: "aud-console", CertificatesURL: keyServer.URL + "/cdn-cgi/access/certs",
		ClockSkew: time.Minute, MaxTokenBytes: 16 * 1024, KnownKeyOutageLimit: 24 * time.Hour,
	}, keyServer.Client(), clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	factory := result.NewFactory(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}, func() (string, error) { return "request-real-browser", nil })
	authenticator, err := NewBrowserAuthenticator(BrowserAuthConfig{ExactOrigin: "https://console.example", ExactHost: "console.example", Identities: adapter, Sessions: authority, Results: factory})
	if err != nil {
		t.Fatal(err)
	}
	authorizer := newAuditingReadAuthorizer(store.NewReadAuthorizer(authority), authority)
	application, err := api.NewApplication(api.Config{Authority: authority, Authorizer: authorizer, Reads: store.NewReadRepository(authority), Results: factory, Sessions: authenticator.SessionService()})
	if err != nil {
		t.Fatal(err)
	}
	remote := httptest.NewTLSServer(authenticator.Wrap(application))
	defer remote.Close()

	cookie := createRealBrowserSession(t, remote, assertion)
	assertRemoteStatus(t, remote, assertion, cookie, "/api/v1/summary", http.StatusOK, false)
	renewed := renewRealBrowserSession(t, remote, assertion, cookie)
	assertRemoteStatus(t, remote, assertion, cookie, "/api/v1/summary", http.StatusUnauthorized, false)
	assertRemoteStatus(t, remote, assertion, renewed, "/api/v1/summary", http.StatusOK, false)
	logoutRealBrowserSession(t, remote, assertion, renewed, "/api/v1/session/logout", http.StatusOK)
	assertRemoteStatus(t, remote, assertion, renewed, "/api/v1/summary", http.StatusUnauthorized, false)

	revoked := createRealBrowserSession(t, remote, assertion)
	if err := authority.RevokeBrowserSessions(context.Background(), identity.Principal{ID: "principal.remote", Method: identity.CloudflareAccessMethod}, "emergency-revocation"); err != nil {
		t.Fatal(err)
	}
	assertRemoteStatus(t, remote, assertion, revoked, "/api/v1/summary", http.StatusUnauthorized, false)
	revokedAgain := createRealBrowserSession(t, remote, assertion)
	if err := authority.RevokeBrowserSessions(context.Background(), identity.Principal{ID: "principal.remote", Method: identity.CloudflareAccessMethod}, "emergency-revocation"); err != nil {
		t.Fatal(err)
	}
	assertRemoteStatus(t, remote, assertion, revokedAgain, "/api/v1/summary", http.StatusUnauthorized, false)

	grantBound := createRealBrowserSession(t, remote, assertion)
	if err := updateBrowserIntegrationDatabase(databasePath, `UPDATE read_principals SET grant_revision=2,updated_at=? WHERE principal_id='principal.remote'`, clock.Now().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if err := updateBrowserIntegrationDatabase(databasePath, `UPDATE read_grants SET grant_revision=2,updated_at=? WHERE principal_id='principal.remote' AND capability='platform.summary.read'`, clock.Now().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	assertRemoteStatus(t, remote, assertion, grantBound, "/api/v1/summary", http.StatusUnauthorized, false)

	grantDenied := createRealBrowserSession(t, remote, assertion)
	if err := updateBrowserIntegrationDatabase(databasePath, `UPDATE read_grants SET status='revoked',updated_at=? WHERE principal_id='principal.remote' AND capability='platform.summary.read'`, clock.Now().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	assertRemoteStatus(t, remote, assertion, grantDenied, "/api/v1/summary", http.StatusForbidden, false)
	assertRemoteStatus(t, remote, assertion, grantDenied, "/api/v1/inventory-drafts/private-canary/revisions/not-a-number", http.StatusForbidden, true)
	assertReadDenialsSanitized(t, databasePath, 2, "private-canary", "not-a-number")

	recoveryBound := createRealBrowserSession(t, remote, assertion)
	localPrincipal := identity.Principal{ID: "principal.local", Method: identity.LocalOSPeerMethod}
	if err := updateBrowserIntegrationDatabase(databasePath, `UPDATE system_meta SET recovery_epoch=recovery_epoch+1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err := authority.InvalidateBrowserSessionsForRecoveryEpoch(context.Background(), localPrincipal); err != nil {
		t.Fatal(err)
	}
	assertRemoteStatus(t, remote, assertion, recoveryBound, "/api/v1/summary", http.StatusUnauthorized, false)

	providerAvailable.Store(false)
	keyServer.CloseClientConnections()
	clock.Advance(25 * time.Hour)
	assertRemoteStatus(t, remote, assertion, nil, "/api/v1/session", http.StatusUnauthorized, false)

	profile := serverconfig.Profile{
		SocketPath: filepath.Join(directory, "control.sock"), SocketOwnerUID: uint32(os.Getuid()), SocketMode: 0o600,
		ShutdownGrace: 5 * time.Second, PrincipalBindings: []identity.Binding{{UID: uint32(os.Getuid()), PrincipalID: localPrincipal.ID}},
	}
	service, err := New(Config{Profile: profile, Application: application, Results: factory, PlatformProbe: staticPlatformProbe{platform: testSupportedPlatform()}, IntegrityInterval: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	serviceContext, cancelService := context.WithCancel(context.Background())
	serviceDone := make(chan error, 1)
	go func() { serviceDone <- service.Run(serviceContext) }()
	client := localapi.NewClient(factory)
	var localErr error
	localSucceeded := false
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		response, requestErr := client.Status(context.Background(), profile)
		if requestErr == nil && response.ExitCode == 0 && response.Status.ReadAvailable {
			localSucceeded = true
			break
		}
		if requestErr != nil {
			localErr = requestErr
		} else {
			localErr = fmt.Errorf("local status exit=%d readAvailable=%t", response.ExitCode, response.Status.ReadAvailable)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !localSucceeded {
		cancelService()
		<-serviceDone
		t.Fatalf("local recovery status: %v", localErr)
	}
	cancelService()
	if err := <-serviceDone; err != nil {
		t.Fatal(err)
	}
}

func assertReadDenialsSanitized(t *testing.T, databasePath string, want int, canaries ...string) {
	t.Helper()
	database, err := sql.Open("sqlite3", (&url.URL{Scheme: "file", Path: databasePath}).String())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	rows, err := database.Query(`SELECT canonical_payload FROM audit_events WHERE event_type='authorization.read-denied' ORDER BY event_id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			t.Fatal(err)
		}
		for _, canary := range canaries {
			if strings.Contains(payload, canary) {
				t.Fatalf("authorization denial audit leaked %q", canary)
			}
		}
		count++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if count != want {
		t.Fatalf("authorization denial audits = %d, want %d", count, want)
	}
}

func signBrowserIntegrationJWT(t *testing.T, key *rsa.PrivateKey, keyID, issuer string, now time.Time, lifetime time.Duration) string {
	t.Helper()
	options := (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", keyID)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, options)
	if err != nil {
		t.Fatal(err)
	}
	serialized, err := jwt.Signed(signer).Claims(jwt.Claims{
		Issuer: issuer, Subject: "subject-real-browser", Audience: jwt.Audience{"aud-console"},
		IssuedAt: jwt.NewNumericDate(now.Add(-time.Minute)), NotBefore: jwt.NewNumericDate(now.Add(-time.Minute)), Expiry: jwt.NewNumericDate(now.Add(lifetime)),
	}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return serialized
}

func seedBrowserIntegrationAuthority(t *testing.T, databasePath, bindingDigest string, now time.Time) {
	t.Helper()
	database, err := sql.Open("sqlite3", (&url.URL{Scheme: "file", Path: databasePath}).String())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.Exec(`PRAGMA foreign_keys=ON`); err != nil {
		t.Fatal(err)
	}
	formatted := now.UTC().Format(time.RFC3339Nano)
	for _, principal := range []string{"principal.remote", "principal.local"} {
		if _, err := database.Exec(`INSERT INTO read_principals(principal_id,status,grant_revision,created_at,updated_at) VALUES(?,'active',1,?,?)`, principal, formatted, formatted); err != nil {
			t.Fatal(err)
		}
	}
	for _, grant := range []struct{ principal, capability, kind, resource string }{
		{"principal.remote", "platform.summary.read", "platform-summary", "summary"},
		{"principal.local", "control.health.read", "control", "health"},
		{"principal.local", "platform.summary.read", "platform-summary", "summary"},
	} {
		if _, err := database.Exec(`INSERT INTO read_grants(principal_id,capability,resource_kind,resource_id,grant_revision,status,created_at,updated_at) VALUES(?,?,?,?,1,'active',?,?)`, grant.principal, grant.capability, grant.kind, grant.resource, formatted, formatted); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := database.Exec(`INSERT INTO remote_identity_bindings(binding_digest,principal_id,status,created_at,updated_at) VALUES(?,'principal.remote','active',?,?)`, bindingDigest, formatted, formatted); err != nil {
		t.Fatal(err)
	}
}

func updateBrowserIntegrationDatabase(databasePath, statement string, arguments ...any) error {
	database, err := sql.Open("sqlite3", (&url.URL{Scheme: "file", Path: databasePath, RawQuery: "_txlock=immediate"}).String())
	if err != nil {
		return err
	}
	defer database.Close()
	_, err = database.Exec(statement, arguments...)
	return err
}

func createRealBrowserSession(t *testing.T, host *httptest.Server, assertion string) *http.Cookie {
	t.Helper()
	response := realBrowserRequest(t, host, assertion, nil, http.MethodPost, "/api/v1/session")
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("create status = %d %s", response.StatusCode, body)
	}
	for _, cookie := range response.Cookies() {
		if cookie.Name == BrowserSessionCookieName && cookie.Value != "" {
			return cookie
		}
	}
	t.Fatal("create response omitted session cookie")
	return nil
}

func renewRealBrowserSession(t *testing.T, host *httptest.Server, assertion string, cookie *http.Cookie) *http.Cookie {
	t.Helper()
	response := realBrowserRequest(t, host, assertion, cookie, http.MethodPost, "/api/v1/session/renew")
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("renew status = %d", response.StatusCode)
	}
	for _, next := range response.Cookies() {
		if next.Name == BrowserSessionCookieName && next.Value != "" && next.Value != cookie.Value {
			return next
		}
	}
	t.Fatal("renew response omitted rotated session cookie")
	return nil
}

func logoutRealBrowserSession(t *testing.T, host *httptest.Server, assertion string, cookie *http.Cookie, path string, expected int) {
	t.Helper()
	response := realBrowserRequest(t, host, assertion, cookie, http.MethodPost, path)
	defer response.Body.Close()
	if response.StatusCode != expected {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("logout status = %d %s", response.StatusCode, body)
	}
	for _, cleared := range response.Cookies() {
		if cleared.Name == BrowserSessionCookieName && cleared.Value == "" && cleared.MaxAge < 0 {
			return
		}
	}
	t.Fatal("logout response did not clear session cookie")
}

func assertRemoteStatus(t *testing.T, host *httptest.Server, assertion string, cookie *http.Cookie, path string, expected int, privateCanary bool) {
	t.Helper()
	method := http.MethodGet
	if path == "/api/v1/session" {
		method = http.MethodPost
	}
	response := realBrowserRequest(t, host, assertion, cookie, method, path)
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != expected || privateCanary && strings.Contains(string(body), "private-canary") {
		t.Fatalf("%s status/body = %d %s", path, response.StatusCode, body)
	}
}

func realBrowserRequest(t *testing.T, host *httptest.Server, assertion string, cookie *http.Cookie, method, path string) *http.Response {
	t.Helper()
	var body io.Reader
	if method == http.MethodPost {
		body = strings.NewReader(`{"requestVersion":"1.0.0"}`)
	}
	request, err := http.NewRequest(method, host.URL+path, body)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "console.example"
	request.Header.Set("Cf-Access-Jwt-Assertion", assertion)
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", "https://console.example")
	} else {
		request.Header.Set("Sec-Fetch-Site", "same-origin")
		request.Header.Set("Sec-Fetch-Mode", "cors")
		request.Header.Set("Sec-Fetch-Dest", "empty")
	}
	if cookie != nil {
		request.AddCookie(cookie)
	}
	response, err := host.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}
