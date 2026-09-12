//go:build linux

package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
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
	"github.com/vegastack/vegastack-labs/internal/generated"
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

type phase3ExecutableFixture struct {
	t              *testing.T
	baseURL        string
	controllerURL  string
	assertion      string
	profile        serverconfig.Profile
	configPath     string
	binaryPath     string
	providerOnline atomic.Bool
	keyServer      *httptest.Server
	command        *exec.Cmd
	done           chan error
	serverStdout   *boundedProbeOutput
	serverStderr   *boundedProbeOutput
}

func newPhase3ExecutableFixture(t *testing.T) *phase3ExecutableFixture {
	t.Helper()
	binaryPath := os.Getenv("VSK_PHASE3_BINARY")
	runtimeRoot := os.Getenv("VSK_PHASE3_RUNTIME_ROOT")
	if !filepath.IsAbs(binaryPath) || !filepath.IsAbs(runtimeRoot) {
		t.Skip("built-executable acceptance runs through pnpm check:phase-3")
	}
	now := time.Now().UTC().Truncate(time.Second)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const keyID = "phase3-executable-key"
	fixture := &phase3ExecutableFixture{t: t, binaryPath: binaryPath, done: make(chan error, 1)}
	fixture.providerOnline.Store(true)
	fixture.keyServer = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		if !fixture.providerOnline.Load() {
			http.Error(writer, "provider unavailable", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(writer).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: keyID, Algorithm: string(jose.RS256), Use: "sig"}}})
	}))
	t.Cleanup(fixture.keyServer.Close)
	fixture.assertion = signBrowserIntegrationJWT(t, key, keyID, fixture.keyServer.URL, now, time.Hour)
	verified := identity.VerifiedIdentity{Issuer: fixture.keyServer.URL, Subject: "subject-real-browser", Audiences: []string{"aud-console"}, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Method: identity.CloudflareAccessMethod}
	binding, err := identity.BindingDigest(verified)
	if err != nil {
		t.Fatal(err)
	}

	databasePath := filepath.Join(runtimeRoot, "control.db")
	uid := uint32(os.Getuid())
	initial, err := store.Open(context.Background(), store.Config{DatabasePath: databasePath, Mode: store.InitializeNew, ExpectedUID: uid, ToolVersion: "phase3-test", BuildVersion: "phase3-test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := initial.Close(); err != nil {
		t.Fatal(err)
	}
	seedBrowserIntegrationAuthority(t, databasePath, binding, now)
	seedPhase3SourceGrants(t, databasePath, now)
	certificatePath, keyPath := writeRemoteTestCertificate(t)
	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reserved.Addr().String()
	if err := reserved.Close(); err != nil {
		t.Fatal(err)
	}
	fixture.baseURL = "https://" + address
	exportRoot := filepath.Join(runtimeRoot, "exports")
	if err := os.Mkdir(exportRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	identityPath := filepath.Join(runtimeRoot, "cloudflare-access.json")
	writeProtectedJSON(t, identityPath, generated.CloudflareAccessProfile{
		Schema: generated.SchemaIDCloudflareAccessProfile, SchemaVersion: "1.0.0", Issuer: fixture.keyServer.URL,
		Audience: "aud-console", CertificatesURL: fixture.keyServer.URL + "/cdn-cgi/access/certs", ClockSkewSeconds: 30,
		MaxTokenBytes: 16 * 1024, KnownKeyOutageSeconds: 1,
	})
	remote := generated.RemoteReadProfile{
		Enabled: true, BindAddress: testStringPointer(address), PublicOrigin: testStringPointer(fixture.baseURL),
		TLSCertificatePath: testStringPointer(certificatePath), TLSPrivateKeyPath: testStringPointer(keyPath),
		IdentityAdapter: testStringPointer("cloudflare-access"), IdentityConfigPath: testStringPointer(identityPath),
	}
	generatedProfile := generated.ServerProfile{
		Schema: generated.SchemaIDServerProfile, SchemaVersion: "1.1.0", SocketPath: filepath.Join(runtimeRoot, "control.sock"),
		SocketOwnerUID: int64(uid), SocketMode: "0600", ShutdownGraceSeconds: 5, InventoryExportRoot: exportRoot,
		PrincipalBindings: []generated.LocalPrincipalBinding{{UID: int64(uid), PrincipalID: "principal.local"}}, RemoteRead: remote,
	}
	fixture.configPath = filepath.Join(runtimeRoot, "server-profile.json")
	writeProtectedJSON(t, fixture.configPath, generatedProfile)
	fixture.profile, err = serverconfig.NewLoader(uid).Load(context.Background(), fixture.configPath)
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(runtimeRoot, "jwks-ca.pem")
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fixture.keyServer.Certificate().Raw})
	if err := os.WriteFile(caPath, ca, 0o600); err != nil {
		t.Fatal(err)
	}
	fixture.command = exec.Command(binaryPath, "server", "run", "--config", fixture.configPath, "--output", "json")
	fixture.command.Env = append(os.Environ(), "SSL_CERT_FILE="+caPath)
	fixture.serverStdout = &boundedProbeOutput{limit: 16 * 1024}
	fixture.serverStderr = &boundedProbeOutput{limit: 512}
	fixture.command.Stdout = fixture.serverStdout
	fixture.command.Stderr = fixture.serverStderr
	if err := fixture.command.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { fixture.done <- fixture.command.Wait() }()
	t.Cleanup(func() {
		_ = fixture.command.Process.Signal(os.Interrupt)
		select {
		case runErr := <-fixture.done:
			if runErr != nil {
				t.Errorf("built vsk-labs server stopped unsuccessfully")
			}
		case <-time.After(7 * time.Second):
			_ = fixture.command.Process.Kill()
			t.Error("built vsk-labs server did not stop")
		}
	})

	factory := result.NewFactory(result.BuildInfo{ToolVersion: "phase3-test", ReleaseBuildID: "phase3-test"}, func() (string, error) { return "request-phase3-executable", nil })
	client := localapi.NewClient(factory)
	ready := false
	startupReason := "unreachable"
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		status, statusErr := client.Status(context.Background(), fixture.profile)
		if statusErr == nil {
			startupReason = status.Status.RemoteReadReason
		}
		if statusErr == nil && status.ExitCode == 0 && status.Status.ReadAvailable && status.Status.RemoteReadState == string(RemoteReadReady) {
			ready = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		select {
		case runErr := <-fixture.done:
			fixture.done <- runErr
			startupReason = phase3ExecutableStartupReason(fixture.serverStdout.Bytes())
		default:
		}
		t.Fatalf("built vsk-labs server did not become ready: REMOTE_REASON:%s", startupReason)
	}
	controller := httptest.NewServer(fixture.controller())
	fixture.controllerURL = controller.URL
	t.Cleanup(controller.Close)
	return fixture
}

func phase3ExecutableStartupReason(output []byte) string {
	var envelope struct {
		Errors []struct {
			Code   string `json:"code"`
			Target string `json:"target"`
		} `json:"errors"`
	}
	if json.Unmarshal(output, &envelope) != nil || len(envelope.Errors) != 1 {
		return "unreachable"
	}
	stable := func(value string) bool {
		return value != "" && len(value) <= 64 && strings.IndexFunc(value, func(character rune) bool {
			return character != '-' && character != '_' && character != '.' && (character < '0' || character > '9') && (character < 'A' || character > 'Z') && (character < 'a' || character > 'z')
		}) == -1
	}
	if !stable(envelope.Errors[0].Code) || !stable(envelope.Errors[0].Target) {
		return "unreachable"
	}
	return strings.ToLower(strings.ReplaceAll(envelope.Errors[0].Code+"-"+envelope.Errors[0].Target, "_", "-"))
}

func TestPhase3AcceptanceStartupReasonAllowsOnlyStableEnvelopeFields(t *testing.T) {
	if got := phase3ExecutableStartupReason([]byte(`{"errors":[{"code":"INPUT_INVALID","target":"server-config"}]}`)); got != "input-invalid-server-config" {
		t.Fatalf("startup reason = %q", got)
	}
	for _, unsafe := range []string{
		`{"errors":[{"code":"INPUT_INVALID","target":"/private/path"}]}`,
		`{"errors":[{"code":"INPUT_INVALID","target":"server config"}]}`,
		`not-json`,
	} {
		if got := phase3ExecutableStartupReason([]byte(unsafe)); got != "unreachable" {
			t.Fatalf("unsafe startup reason = %q", got)
		}
	}
}

func (fixture *phase3ExecutableFixture) controller() http.Handler {
	// The built server remains the only Store owner. These synthetic controls use
	// short SQLite updates so the fixture never competes for the writer lock.
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
	post("/expire", func() error {
		return updateBrowserIntegrationDatabase(filepath.Join(os.Getenv("VSK_PHASE3_RUNTIME_ROOT"), "control.db"), `UPDATE browser_sessions SET idle_expires_at=? WHERE status='active'`, time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano))
	})
	post("/revoke", func() error {
		now := time.Now().UTC().Format(time.RFC3339Nano)
		return updateBrowserIntegrationDatabase(filepath.Join(os.Getenv("VSK_PHASE3_RUNTIME_ROOT"), "control.db"), `UPDATE browser_sessions SET status='revoked',ended_at=?,end_reason='emergency-revocation' WHERE principal_id='principal.remote' AND status='active'`, now)
	})
	post("/provider-outage", func() error {
		fixture.providerOnline.Store(false)
		fixture.keyServer.CloseClientConnections()
		time.Sleep(1100 * time.Millisecond)
		return nil
	})
	post("/provider-recover", func() error { fixture.providerOnline.Store(true); return nil })
	denial := func(path string, mutate func(*http.Request)) {
		mux.HandleFunc(path, func(writer http.ResponseWriter, request *http.Request) {
			if request.Method != http.MethodGet {
				http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			probe, err := http.NewRequest(http.MethodGet, fixture.baseURL+"/", nil)
			if err != nil {
				http.Error(writer, "fixture operation failed", http.StatusInternalServerError)
				return
			}
			probe.Header.Set("Cf-Access-Jwt-Assertion", fixture.assertion)
			probe.Header.Set("Origin", fixture.baseURL)
			probe.Header.Set("Sec-Fetch-Site", "same-origin")
			probe.Header.Set("Sec-Fetch-Mode", "cors")
			probe.Header.Set("Sec-Fetch-Dest", "empty")
			mutate(probe)
			response, err := (&http.Client{Transport: &http.Transport{TLSClientConfig: insecurePhase3TLSConfig()}, Timeout: 5 * time.Second}).Do(probe)
			if err != nil {
				http.Error(writer, "fixture operation failed", http.StatusInternalServerError)
				return
			}
			defer response.Body.Close()
			writer.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(writer, fmt.Sprintf(`{"statusCode":%d}`, response.StatusCode))
		})
	}
	denial("/wrong-host", func(request *http.Request) { request.Host = "wrong.invalid" })
	denial("/wrong-origin", func(request *http.Request) { request.Header.Set("Origin", "https://wrong.invalid") })
	mux.HandleFunc("/local-status", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		command := exec.Command(fixture.binaryPath, "server", "status", "--config", fixture.configPath, "--output", "json")
		command.Stdout = &boundedProbeOutput{limit: 16 * 1024}
		command.Stderr = &boundedProbeOutput{limit: 512}
		if err := command.Run(); err != nil {
			http.Error(writer, "local recovery unavailable", http.StatusServiceUnavailable)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"status":"succeeded"}`)
	})
	return mux
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
		return fixture.authority.RevokeBrowserSessions(context.Background(), identity.Principal{ID: "principal.remote", Method: identity.CloudflareAccessMethod}, "emergency-revocation")
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
	if response.StatusCode != http.StatusNotFound {
		response.Body.Close()
		t.Fatalf("forbidden summary method = %d", response.StatusCode)
	}
	response.Body.Close()
	if err := fixture.authority.RevokeBrowserSessions(context.Background(), identity.Principal{ID: "principal.remote", Method: identity.CloudflareAccessMethod}, "emergency-revocation"); err != nil {
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
	fixture := newPhase3ExecutableFixture(t)
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
	for _, field := range strings.Fields(value) {
		stage := strings.TrimPrefix(field, "PROBE_FAILED:")
		if stage != field && stage != "" && len(stage) <= 48 && strings.IndexFunc(stage, func(character rune) bool {
			return character != '-' && (character < 'a' || character > 'z')
		}) == -1 {
			return "PROBE_FAILED:" + stage
		}
	}
	return "PROBE_FAILED_WITH_SANITIZED_DIAGNOSTIC"
}

func TestSanitizePhase3ProbeErrorOnlyAllowsStableStages(t *testing.T) {
	for _, test := range []struct{ input, expected string }{
		{"", "PROBE_FAILED"},
		{"PROBE_FAILED:mobile", "PROBE_FAILED:mobile"},
		{"browser noise\nPROBE_FAILED:routes\nmore noise", "PROBE_FAILED:routes"},
		{"PROBE_FAILED:", "PROBE_FAILED_WITH_SANITIZED_DIAGNOSTIC"},
		{"PROBE_FAILED:mobile /home/private", "PROBE_FAILED:mobile"},
		{"Error: token detail", "PROBE_FAILED_WITH_SANITIZED_DIAGNOSTIC"},
	} {
		if actual := sanitizePhase3ProbeError(test.input); actual != test.expected {
			t.Fatalf("sanitized probe error = %q, want %q", actual, test.expected)
		}
	}
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
