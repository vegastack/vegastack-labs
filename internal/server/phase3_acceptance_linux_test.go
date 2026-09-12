//go:build linux

package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/consoleassets"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"github.com/vegastack/vegastack-labs/internal/readmodel"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type phase3AcceptanceFixture struct {
	t              *testing.T
	baseURL        string
	controllerURL  string
	assertion      string
	authority      *store.Store
	clock          *browserIntegrationClock
	profile        serverconfig.Profile
	cancel         context.CancelFunc
	done           chan error
	remoteListener net.Listener
}

func newPhase3AcceptanceServer(t *testing.T) *phase3AcceptanceFixture {
	t.Helper()
	clock := &browserIntegrationClock{at: time.Date(2026, 9, 12, 8, 0, 0, 0, time.UTC)}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const keyID = "phase3-acceptance-key"
	var providerAvailable atomic.Bool
	providerAvailable.Store(true)
	keyServer := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		if !providerAvailable.Load() {
			http.Error(writer, "private-provider-canary", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(writer).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: keyID, Algorithm: string(jose.RS256), Use: "sig"}}})
	}))
	t.Cleanup(keyServer.Close)
	assertion := signBrowserIntegrationJWT(t, key, keyID, keyServer.URL, clock.Now(), 30*time.Hour)
	verified := identity.VerifiedIdentity{Issuer: keyServer.URL, Subject: "subject-real-browser", Audiences: []string{"aud-console"}, IssuedAt: clock.Now().Add(-time.Minute), ExpiresAt: clock.Now().Add(30 * time.Hour), Method: identity.CloudflareAccessMethod}
	binding, err := identity.BindingDigest(verified)
	if err != nil {
		t.Fatal(err)
	}

	directory, err := os.MkdirTemp("", "p3")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(directory, "control.db")
	storeConfig := store.Config{DatabasePath: databasePath, Mode: store.InitializeNew, ExpectedUID: uint32(os.Getuid()), ToolVersion: "phase3-test", BuildVersion: "phase3-test", Clock: clock.Now}
	initial, err := store.Open(context.Background(), storeConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := initial.Close(); err != nil {
		t.Fatal(err)
	}
	seedBrowserIntegrationAuthority(t, databasePath, binding, clock.Now())
	seedPhase3SourceGrants(t, databasePath, clock.Now())
	storeConfig.Mode = store.OpenExisting
	authority, err := store.Open(context.Background(), storeConfig)
	if err != nil {
		t.Fatal(err)
	}

	certificatePath, keyPath := writeRemoteTestCertificate(t)
	listenConfig := RemoteListenConfig{Address: "127.0.0.1:0", CertificatePath: certificatePath, PrivateKeyPath: keyPath}
	listener, err := RemoteListen(context.Background(), listenConfig)
	if err != nil {
		_ = authority.Close()
		t.Fatal(err)
	}
	address := listener.Addr().String()
	baseURL := "https://" + address
	factory := result.NewFactory(result.BuildInfo{ToolVersion: "phase3-test", ReleaseBuildID: "phase3-test"}, func() (string, error) { return "request-phase3-acceptance", nil })
	adapter, err := identity.NewCloudflareAccessAdapter(identity.CloudflareAccessConfig{
		Issuer: keyServer.URL, Audience: "aud-console", CertificatesURL: keyServer.URL + "/cdn-cgi/access/certs",
		ClockSkew: time.Minute, MaxTokenBytes: 16 * 1024, KnownKeyOutageLimit: 24 * time.Hour,
	}, keyServer.Client(), clock.Now)
	if err != nil {
		_ = listener.Close()
		_ = authority.Close()
		t.Fatal(err)
	}
	if err := adapter.Refresh(context.Background()); err != nil {
		_ = listener.Close()
		_ = authority.Close()
		t.Fatal(err)
	}
	authenticator, err := NewBrowserAuthenticator(BrowserAuthConfig{ExactOrigin: baseURL, ExactHost: address, Identities: adapter, Sessions: authority, Results: factory})
	if err != nil {
		_ = listener.Close()
		_ = authority.Close()
		t.Fatal(err)
	}
	application, err := api.NewApplication(api.Config{Authority: authority, Authorizer: newAuditingReadAuthorizer(store.NewReadAuthorizer(authority), authority), Reads: store.NewReadRepository(authority), Results: factory, Sessions: authenticator.SessionService()})
	if err != nil {
		_ = listener.Close()
		_ = authority.Close()
		t.Fatal(err)
	}
	files, manifest, err := consoleassets.Open()
	if err != nil {
		_ = listener.Close()
		_ = authority.Close()
		t.Fatal(err)
	}
	console, err := NewConsoleHandler(files, manifest)
	if err != nil {
		_ = listener.Close()
		_ = authority.Close()
		t.Fatal(err)
	}
	exportRoot := filepath.Join(directory, "exports")
	if err := os.Mkdir(exportRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	profile := serverconfig.Profile{
		SocketPath: filepath.Join(directory, "control.sock"), InventoryExportRoot: exportRoot,
		SocketOwnerUID: uint32(os.Getuid()), SocketMode: 0o600, ShutdownGrace: 5 * time.Second,
		PrincipalBindings: []identity.Binding{{UID: uint32(os.Getuid()), PrincipalID: "principal.local"}},
		RemoteRead:        serverconfig.RemoteRead{Enabled: true, ConfigurationValid: true},
	}
	service, err := New(Config{
		Profile: profile, Application: application, Results: factory,
		PlatformProbe: staticPlatformProbe{platform: testSupportedPlatform()}, IntegrityInterval: 10 * time.Millisecond,
		Remote: &RemoteConfig{Authenticator: authenticator, Console: console, ListenConfig: listenConfig, ListenerFactory: func(context.Context, RemoteListenConfig) (net.Listener, error) { return listener, nil }},
	})
	if err != nil {
		_ = listener.Close()
		_ = authority.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx) }()

	fixture := &phase3AcceptanceFixture{t: t, baseURL: baseURL, assertion: assertion, authority: authority, clock: clock, profile: profile, cancel: cancel, done: done, remoteListener: listener}
	controller := httptest.NewServer(fixture.controller(providerAvailable.Store, keyServer.CloseClientConnections, factory))
	fixture.controllerURL = controller.URL
	t.Cleanup(func() {
		controller.Close()
		cancel()
		select {
		case runErr := <-done:
			if runErr != nil {
				t.Errorf("phase 3 acceptance server stopped: %v", runErr)
			}
		case <-time.After(5 * time.Second):
			t.Error("phase 3 acceptance server did not stop")
		}
	})
	return fixture
}

func (fixture *phase3AcceptanceFixture) controller(setProvider func(bool), closeProviderConnections func(), factory *result.Factory) http.Handler {
	mux := http.NewServeMux()
	post := func(path string, operation func() error) {
		mux.HandleFunc(path, func(writer http.ResponseWriter, request *http.Request) {
			if request.Method != http.MethodPost {
				http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			if err := operation(); err != nil {
				http.Error(writer, "fixture operation failed", http.StatusInternalServerError)
				return
			}
			writer.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(writer, `{"status":"succeeded"}`)
		})
	}
	post("/expire", func() error { fixture.clock.Advance(16 * time.Minute); return nil })
	post("/revoke", func() error {
		return fixture.authority.RevokeBrowserSessions(context.Background(), identity.Principal{ID: "principal.remote", Method: identity.CloudflareAccessMethod}, "phase3-acceptance-revocation")
	})
	post("/provider-outage", func() error {
		setProvider(false)
		closeProviderConnections()
		fixture.clock.Advance(25 * time.Hour)
		return nil
	})
	mux.HandleFunc("/local-status", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		status, err := localapi.NewClient(factory).Status(request.Context(), fixture.profile)
		if err != nil || status.ExitCode != 0 || !status.Status.ReadAvailable {
			http.Error(writer, "local recovery unavailable", http.StatusServiceUnavailable)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"status":"succeeded"}`)
	})
	return mux
}

func seedPhase3SourceGrants(t *testing.T, databasePath string, now time.Time) {
	t.Helper()
	for _, source := range []readmodel.SourceID{readmodel.SourceDatabase, readmodel.SourceNodes, readmodel.SourceGates, readmodel.SourcePeople, readmodel.SourceServices, readmodel.SourceBackups, readmodel.SourceProviders} {
		if err := updateBrowserIntegrationDatabase(databasePath, `INSERT INTO read_grants(principal_id,capability,resource_kind,resource_id,grant_revision,status,created_at,updated_at) VALUES('principal.remote','platform.source.read','platform-source',?,1,'active',?,?)`, string(source), now.UTC().Format(time.RFC3339Nano), now.UTC().Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPhase3AcceptanceServerFailsClosedAndKeepsLocalRecovery(t *testing.T) {
	fixture := newPhase3AcceptanceServer(t)
	cookie := fixture.createSession()
	response := fixture.request(http.MethodPost, "/api/v1/summary", cookie)
	if response.StatusCode != http.StatusMethodNotAllowed {
		response.Body.Close()
		t.Fatalf("forbidden summary method = %d", response.StatusCode)
	}
	response.Body.Close()
	if err := fixture.authority.RevokeBrowserSessions(context.Background(), identity.Principal{ID: "principal.remote", Method: identity.CloudflareAccessMethod}, "phase3-test-revocation"); err != nil {
		t.Fatal(err)
	}
	response = fixture.request(http.MethodGet, "/api/v1/summary", cookie)
	if response.StatusCode != http.StatusUnauthorized {
		response.Body.Close()
		t.Fatalf("revoked summary = %d", response.StatusCode)
	}
	response.Body.Close()
	status, err := localapi.NewClient(result.NewFactory(result.BuildInfo{ToolVersion: "phase3-test", ReleaseBuildID: "phase3-test"}, func() (string, error) { return "request-phase3-local", nil })).Status(context.Background(), fixture.profile)
	if err != nil || status.ExitCode != 0 || !status.Status.ReadAvailable {
		t.Fatalf("local recovery status = %#v, %v", status.Status, err)
	}
}

func TestPhase3AcceptanceChromiumUsesRealTLSAndSessionBoundary(t *testing.T) {
	fixture := newPhase3AcceptanceServer(t)
	command := exec.Command("node", filepath.Join("..", "..", "web", "e2e", "real-server-probe.mjs"))
	command.Env = append(os.Environ(),
		"NODE_NO_WARNINGS=1",
		"VSK_PHASE3_BASE_URL="+fixture.baseURL,
		"VSK_PHASE3_CONTROLLER_URL="+fixture.controllerURL,
		"VSK_PHASE3_ASSERTION="+fixture.assertion,
	)
	stdout := &boundedProbeOutput{limit: 16 * 1024}
	stderr := &boundedProbeOutput{limit: 512}
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		t.Fatalf("phase 3 Chromium probe failed: %v: %s", err, sanitizePhase3ProbeError(stderr.String()))
	}
	var result struct {
		SchemaVersion int    `json:"schemaVersion"`
		Check         string `json:"check"`
		Status        string `json:"status"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || result.SchemaVersion != 1 || result.Check != "phase-3-real-server" || result.Status != "pass" {
		t.Fatalf("phase 3 Chromium probe returned an invalid result")
	}
}

func sanitizePhase3ProbeError(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "PROBE_FAILED"
	}
	return "PROBE_FAILED_WITH_SANITIZED_DIAGNOSTIC"
}

func (fixture *phase3AcceptanceFixture) createSession() *http.Cookie {
	fixture.t.Helper()
	response := fixture.request(http.MethodPost, "/api/v1/session", nil)
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		fixture.t.Fatalf("phase 3 session create = %d", response.StatusCode)
	}
	for _, cookie := range response.Cookies() {
		if cookie.Name == BrowserSessionCookieName && cookie.Value != "" {
			return cookie
		}
	}
	fixture.t.Fatal("phase 3 session cookie missing")
	return nil
}

func (fixture *phase3AcceptanceFixture) request(method, path string, cookie *http.Cookie) *http.Response {
	fixture.t.Helper()
	var body io.Reader
	if method == http.MethodPost {
		body = strings.NewReader(`{"requestVersion":"1.0.0"}`)
	}
	request, err := http.NewRequest(method, fixture.baseURL+path, body)
	if err != nil {
		fixture.t.Fatal(err)
	}
	request.Header.Set("Cf-Access-Jwt-Assertion", fixture.assertion)
	request.Header.Set("Origin", fixture.baseURL)
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.Header.Set("Sec-Fetch-Mode", "cors")
	request.Header.Set("Sec-Fetch-Dest", "empty")
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		request.AddCookie(cookie)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: insecurePhase3TLSConfig()}, Timeout: 5 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		fixture.t.Fatal(err)
	}
	return response
}

func insecurePhase3TLSConfig() *tls.Config {
	// The certificate is generated inside this loopback-only test fixture.
	return &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true} //nolint:gosec
}
