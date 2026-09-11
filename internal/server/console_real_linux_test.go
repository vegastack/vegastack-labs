//go:build linux

package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/consoleassets"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func TestEmbeddedConsoleAndAuthorizedAPIShareOriginWhileLocalRecoverySurvives(t *testing.T) {
	clock := &browserIntegrationClock{at: time.Date(2026, 9, 11, 6, 0, 0, 0, time.UTC)}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const keyID = "console-stack-key"
	keyServer := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(writer).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: keyID, Algorithm: string(jose.RS256), Use: "sig"}}})
	}))
	t.Cleanup(keyServer.Close)
	assertion := signBrowserIntegrationJWT(t, key, keyID, keyServer.URL, clock.Now(), time.Hour)
	verified := identity.VerifiedIdentity{Issuer: keyServer.URL, Subject: "subject-real-browser", Audiences: []string{"aud-console"}, IssuedAt: clock.Now().Add(-time.Minute), ExpiresAt: clock.Now().Add(time.Hour), Method: identity.CloudflareAccessMethod}
	binding, err := identity.BindingDigest(verified)
	if err != nil {
		t.Fatal(err)
	}

	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(directory, "control.db")
	storeConfig := store.Config{DatabasePath: databasePath, Mode: store.InitializeNew, ExpectedUID: uint32(os.Getuid()), ToolVersion: "test", BuildVersion: "test", Clock: clock.Now}
	initial, err := store.Open(context.Background(), storeConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := initial.Close(); err != nil {
		t.Fatal(err)
	}
	seedBrowserIntegrationAuthority(t, databasePath, binding, clock.Now())
	storeConfig.Mode = store.OpenExisting
	authority, err := store.Open(context.Background(), storeConfig)
	if err != nil {
		t.Fatal(err)
	}

	factory := result.NewFactory(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}, func() (string, error) { return "request-console-stack", nil })
	adapter, err := identity.NewCloudflareAccessAdapter(identity.CloudflareAccessConfig{
		Issuer: keyServer.URL, Audience: "aud-console", CertificatesURL: keyServer.URL + "/cdn-cgi/access/certs",
		ClockSkew: time.Minute, MaxTokenBytes: 16 * 1024, KnownKeyOutageLimit: time.Hour,
	}, keyServer.Client(), clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := NewBrowserAuthenticator(BrowserAuthConfig{ExactOrigin: "https://console.example", ExactHost: "console.example", Identities: adapter, Sessions: authority, Results: factory})
	if err != nil {
		t.Fatal(err)
	}
	application, err := api.NewApplication(api.Config{Authority: authority, Authorizer: newAuditingReadAuthorizer(store.NewReadAuthorizer(authority), authority), Reads: store.NewReadRepository(authority), Results: factory, Sessions: authenticator.SessionService()})
	if err != nil {
		t.Fatal(err)
	}
	files, manifest, err := consoleassets.Open()
	if err != nil {
		t.Fatal(err)
	}
	console, err := NewConsoleHandler(files, manifest)
	if err != nil {
		t.Fatal(err)
	}
	certificatePath, keyPath := writeRemoteTestCertificate(t)
	remoteAddress := make(chan string, 1)
	exportRoot := filepath.Join(directory, "exports")
	if err := os.Mkdir(exportRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	profile := serverconfig.Profile{
		SocketPath: filepath.Join(directory, "control.sock"), InventoryExportRoot: exportRoot, SocketOwnerUID: uint32(os.Getuid()), SocketMode: 0o600,
		ShutdownGrace: 5 * time.Second, PrincipalBindings: []identity.Binding{{UID: uint32(os.Getuid()), PrincipalID: "principal.local"}}, RemoteRead: serverconfig.RemoteRead{Enabled: true, ConfigurationValid: true},
	}
	service, err := New(Config{
		Profile: profile, Application: application, Results: factory, PlatformProbe: staticPlatformProbe{platform: testSupportedPlatform()}, IntegrityInterval: 10 * time.Millisecond,
		Remote: &RemoteConfig{Authenticator: authenticator, Console: console, ListenConfig: RemoteListenConfig{Address: "127.0.0.1:0", CertificatePath: certificatePath, PrivateKeyPath: keyPath}, ListenerFactory: func(ctx context.Context, config RemoteListenConfig) (net.Listener, error) {
			listener, listenErr := RemoteListen(ctx, config)
			if listenErr == nil {
				remoteAddress <- listener.Addr().String()
			}
			return listener, listenErr
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx) }()
	var address string
	select {
	case address = <-remoteAddress:
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("remote listener did not start")
	}

	certificate, err := os.ReadFile(certificatePath)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificate) {
		t.Fatal("test certificate did not parse")
	}
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}}}
	request := consoleStackRequest(t, http.MethodGet, "https://"+address+"/", assertion, nil)
	request.Header.Set("Sec-Fetch-Site", "none")
	request.Header.Set("Sec-Fetch-Mode", "navigate")
	request.Header.Set("Sec-Fetch-Dest", "document")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Security-Policy") == "" {
		t.Fatalf("embedded index = %d", response.StatusCode)
	}
	_ = response.Body.Close()

	for _, target := range []string{"/dashboard", "/%252e%252e/index.html"} {
		request = consoleStackRequest(t, http.MethodGet, "https://"+address+target, assertion, nil)
		request.Header.Set("Sec-Fetch-Site", "same-origin")
		request.Header.Set("Sec-Fetch-Mode", "navigate")
		request.Header.Set("Sec-Fetch-Dest", "document")
		response, err = client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		want := http.StatusOK
		if strings.Contains(target, "%25") {
			want = http.StatusBadRequest
		}
		if response.StatusCode != want {
			t.Fatalf("embedded route %s = %d, want %d", target, response.StatusCode, want)
		}
		_ = response.Body.Close()
	}
	var scriptPath string
	for name, asset := range manifest.Files {
		if asset.Immutable && strings.HasSuffix(name, ".js") {
			scriptPath = "/" + name
			break
		}
	}
	if scriptPath == "" {
		t.Fatal("embedded manifest has no immutable script")
	}
	request = consoleStackRequest(t, http.MethodGet, "https://"+address+scriptPath, assertion, nil)
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.Header.Set("Sec-Fetch-Mode", "no-cors")
	request.Header.Set("Sec-Fetch-Dest", "script")
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "public, max-age=31536000, immutable" {
		t.Fatalf("embedded script = %d %q", response.StatusCode, response.Header.Get("Cache-Control"))
	}
	_ = response.Body.Close()

	for _, negative := range []struct {
		method string
		path   string
		want   int
	}{
		{method: http.MethodGet, path: "/missing-console-asset.js", want: http.StatusNotFound},
		{method: http.MethodDelete, path: "/dashboard", want: http.StatusMethodNotAllowed},
	} {
		request = consoleStackRequest(t, negative.method, "https://"+address+negative.path, assertion, nil)
		request.Header.Set("Sec-Fetch-Site", "same-origin")
		request.Header.Set("Sec-Fetch-Mode", "cors")
		request.Header.Set("Sec-Fetch-Dest", "empty")
		response, err = client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != negative.want {
			t.Fatalf("%s %s = %d, want %d", negative.method, negative.path, response.StatusCode, negative.want)
		}
		_ = response.Body.Close()
	}

	response, err = client.Do(consoleStackRequest(t, http.MethodPost, "https://"+address+"/api/v1/session", assertion, nil))
	if err != nil {
		t.Fatal(err)
	}
	var session *http.Cookie
	for _, cookie := range response.Cookies() {
		if cookie.Name == BrowserSessionCookieName && cookie.Value != "" {
			session = cookie
		}
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || session == nil {
		t.Fatalf("session bootstrap = %d", response.StatusCode)
	}
	summaryPath := generatedEndpointPath(t, "api.v1.summary.get")
	response, err = client.Do(consoleStackRequest(t, http.MethodGet, "https://"+address+summaryPath, assertion, session))
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("same-origin summary = %d", response.StatusCode)
	}
	var remoteEnvelope generated.RunResult
	if err := json.NewDecoder(response.Body).Decode(&remoteEnvelope); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	var remoteSummary generated.ApiSummaryData
	if err := json.Unmarshal(remoteEnvelope.Data, &remoteSummary); err != nil {
		t.Fatal(err)
	}
	generatedSummary := generatedReadClientSummary(t, address, certificatePath, assertion, session)
	if generatedSummary != remoteSummary {
		t.Fatalf("generated client summary mismatch = %#v / %#v", generatedSummary, remoteSummary)
	}

	response, err = client.Do(consoleStackRequest(t, http.MethodGet, "https://"+address+"/api/v1/not-a-route", assertion, session))
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown remote API route = %d", response.StatusCode)
	}
	_ = response.Body.Close()

	forged := consoleStackRequest(t, http.MethodGet, "https://"+address+"/", assertion, nil)
	forged.Host = "direct-origin.invalid"
	forged.Header.Set("X-Forwarded-Host", "console.example")
	forged.Header.Set("X-Forwarded-Proto", "https")
	forged.Header.Set("Sec-Fetch-Site", "none")
	forged.Header.Set("Sec-Fetch-Mode", "navigate")
	forged.Header.Set("Sec-Fetch-Dest", "document")
	response, err = client.Do(forged)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("forwarded identity changed admission: %d", response.StatusCode)
	}
	_ = response.Body.Close()

	response, err = client.Do(consoleStackRequest(t, http.MethodPost, "https://"+address+"/api/v1/inventory-drafts/import", assertion, session))
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("remote mutation route = %d", response.StatusCode)
	}
	_ = response.Body.Close()

	localClient := localapi.NewClient(factory)
	localStatus, err := localClient.Status(context.Background(), profile)
	if err != nil || localStatus.Status.RemoteReadState != "ready" || !localStatus.Status.ReadAvailable {
		t.Fatalf("local recovery status = %#v, %v", localStatus.Status, err)
	}
	localSummary, err := localClient.Summary(context.Background(), profile)
	if err != nil || localSummary.Data != remoteSummary {
		t.Fatalf("local/remote summary mismatch = %#v / %#v, %v", localSummary.Data, remoteSummary, err)
	}

	unknownKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	unknownAssertion := signBrowserIntegrationJWT(t, unknownKey, "unknown-key", keyServer.URL, clock.Now(), time.Hour)
	keyServer.Close()
	response, err = client.Do(consoleStackRequest(t, http.MethodGet, "https://"+address+summaryPath, unknownAssertion, session))
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("remote identity outage = %d", response.StatusCode)
	}
	_ = response.Body.Close()
	if recovered, err := localClient.Summary(context.Background(), profile); err != nil || recovered.Data != localSummary.Data {
		t.Fatalf("local read after remote identity outage = %#v, %v", recovered.Data, err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestInvalidRemoteConfigurationLeavesRealLocalUnixServiceAvailable(t *testing.T) {
	directory := t.TempDir()
	profile := serverconfig.Profile{
		SocketPath: filepath.Join(directory, "control.sock"), SocketOwnerUID: uint32(os.Getuid()), SocketMode: 0o600,
		ShutdownGrace: 5 * time.Second, PrincipalBindings: []identity.Binding{{UID: uint32(os.Getuid()), PrincipalID: "principal.local"}},
		RemoteRead: serverconfig.RemoteRead{Enabled: true},
	}
	factory := result.NewFactory(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}, func() (string, error) { return "request-invalid-remote", nil })
	application := &healthAuthorizedApplication{testApplication: testApplication{health: ApplicationHealth{StateRevision: 3, RecoveryEpoch: 1}}}
	service, err := New(Config{
		Profile: profile, Application: application, Results: factory, PlatformProbe: staticPlatformProbe{platform: testSupportedPlatform()},
		Remote: &RemoteConfig{PreflightFailure: RemoteReadReasonPreflightUnavailable},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx) }()
	client := localapi.NewClient(factory)
	var status localapi.Response
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		status, err = client.Status(context.Background(), profile)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil || status.Status.RemoteReadState != "unavailable" || status.Status.RemoteReadReason != "preflight-unavailable" || !status.Status.ReadAvailable {
		t.Fatalf("local status with invalid remote = %#v, %v", status.Status, err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRealRemoteBindFailureLeavesLocalUnixServiceAvailable(t *testing.T) {
	directory := t.TempDir()
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	certificatePath, keyPath := writeRemoteTestCertificate(t)
	authenticator, _, _ := newBrowserAuthFixture(t)
	profile := serverconfig.Profile{
		SocketPath: filepath.Join(directory, "control.sock"), SocketOwnerUID: uint32(os.Getuid()), SocketMode: 0o600,
		ShutdownGrace: 5 * time.Second, PrincipalBindings: []identity.Binding{{UID: uint32(os.Getuid()), PrincipalID: "principal.local"}},
		RemoteRead: serverconfig.RemoteRead{Enabled: true, ConfigurationValid: true},
	}
	factory := result.NewFactory(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}, func() (string, error) { return "request-bind-failure", nil })
	application := &healthAuthorizedApplication{testApplication: testApplication{health: ApplicationHealth{StateRevision: 4, RecoveryEpoch: 1}}}
	service, err := New(Config{
		Profile: profile, Application: application, Results: factory, PlatformProbe: staticPlatformProbe{platform: testSupportedPlatform()},
		Remote: &RemoteConfig{Authenticator: authenticator, Console: testConsoleHandler(t), ListenConfig: RemoteListenConfig{Address: occupied.Addr().String(), CertificatePath: certificatePath, PrivateKeyPath: keyPath}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx) }()
	client := localapi.NewClient(factory)
	var status localapi.Response
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		status, err = client.Status(context.Background(), profile)
		if err == nil && status.Status.RemoteReadState == "unavailable" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil || status.Status.RemoteReadReason != "listener-unavailable" || !status.Status.ReadAvailable {
		t.Fatalf("local status after remote bind failure = %#v, %v", status.Status, err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestProductionOperationsInvalidRemoteConfigurationKeepsRealStoreAPIAvailable(t *testing.T) {
	operations, profile, configPath, factory := productionOperationsFixture(t, generated.RemoteReadProfile{Enabled: true})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- operations.Run(ctx, configPath) }()
	client := localapi.NewClient(factory)
	summary := awaitProductionSummary(t, client, profile, done)
	if !summary.Data.ReadAvailable {
		t.Fatalf("production local summary unavailable: %#v", summary.Data)
	}
	status, err := client.Status(context.Background(), profile)
	if err != nil || status.Status.RemoteReadState != "unavailable" || status.Status.RemoteReadReason != "preflight-unavailable" {
		t.Fatalf("production invalid-remote status = %#v, %v", status.Status, err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestProductionOperationsRemoteBindFailureKeepsRealStoreAPIAvailable(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	certificatePath, keyPath := writeRemoteTestCertificate(t)
	identityDirectory := t.TempDir()
	if err := os.Chmod(identityDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	identityConfigPath := filepath.Join(identityDirectory, "cloudflare-access.json")
	identityProfile := generated.CloudflareAccessProfile{
		Schema: generated.SchemaIDCloudflareAccessProfile, SchemaVersion: "1.0.0",
		Issuer: "https://team.cloudflareaccess.com", Audience: "audience-id", CertificatesURL: "https://team.cloudflareaccess.com/cdn-cgi/access/certs",
		ClockSkewSeconds: 30, MaxTokenBytes: 16 * 1024, KnownKeyOutageSeconds: 3600,
	}
	writeProtectedJSON(t, identityConfigPath, identityProfile)
	remote := generated.RemoteReadProfile{
		Enabled: true, BindAddress: testStringPointer(occupied.Addr().String()), PublicOrigin: testStringPointer("https://console.example"),
		TLSCertificatePath: testStringPointer(certificatePath), TLSPrivateKeyPath: testStringPointer(keyPath),
		IdentityAdapter: testStringPointer("cloudflare-access"), IdentityConfigPath: testStringPointer(identityConfigPath),
	}
	operations, profile, configPath, factory := productionOperationsFixture(t, remote)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- operations.Run(ctx, configPath) }()
	client := localapi.NewClient(factory)
	summary := awaitProductionSummary(t, client, profile, done)
	if !summary.Data.ReadAvailable {
		t.Fatalf("production local summary unavailable: %#v", summary.Data)
	}
	var status localapi.Response
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		status, err = client.Status(context.Background(), profile)
		if err == nil && status.Status.RemoteReadState == "unavailable" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil || status.Status.RemoteReadReason != "listener-unavailable" {
		t.Fatalf("production bind-failure status = %#v, %v", status.Status, err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func productionOperationsFixture(t *testing.T, remote generated.RemoteReadProfile) (*Operations, serverconfig.Profile, string, *result.Factory) {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	exportRoot := filepath.Join(directory, "exports")
	if err := os.Mkdir(exportRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Getuid())
	databasePath := filepath.Join(directory, "control.db")
	storeConfig := store.Config{DatabasePath: databasePath, Mode: store.InitializeNew, ExpectedUID: uid, ToolVersion: "test", BuildVersion: "test"}
	authority, err := store.Open(context.Background(), storeConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.Close(); err != nil {
		t.Fatal(err)
	}
	seedBrowserIntegrationAuthority(t, databasePath, strings.Repeat("f", 64), time.Now())
	generatedProfile := generated.ServerProfile{
		Schema: generated.SchemaIDServerProfile, SchemaVersion: "1.1.0",
		SocketPath: filepath.Join(directory, "control.sock"), SocketOwnerUID: int64(uid), SocketMode: "0600", ShutdownGraceSeconds: 5,
		InventoryExportRoot: exportRoot, PrincipalBindings: []generated.LocalPrincipalBinding{{UID: int64(uid), PrincipalID: "principal.local"}}, RemoteRead: remote,
	}
	configPath := filepath.Join(directory, "server-profile.json")
	writeProtectedJSON(t, configPath, generatedProfile)
	profile, err := serverconfig.NewLoader(uid).Load(context.Background(), configPath)
	if err != nil {
		t.Fatal(err)
	}
	build := result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}
	factory := result.NewFactory(build, func() (string, error) { return "request-production-console", nil })
	operations := NewOperations(build, func() (string, error) { return "request-production-console", nil })
	operations.databasePath = databasePath
	return operations, profile, configPath, factory
}

func awaitProductionSummary(t *testing.T, client localapi.Client, profile serverconfig.Profile, done <-chan error) localapi.TypedResponse[generated.ApiSummaryData] {
	t.Helper()
	var summary localapi.TypedResponse[generated.ApiSummaryData]
	var err error
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		select {
		case runErr := <-done:
			t.Fatalf("production operations stopped before local read: %v", runErr)
		default:
		}
		summary, err = client.Summary(context.Background(), profile)
		if err == nil {
			return summary
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("production local summary unavailable: %v", err)
	return summary
}

func writeProtectedJSON(t *testing.T, target string, value any) {
	t.Helper()
	content, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, content, 0o600); err != nil {
		t.Fatal(err)
	}
}

func testStringPointer(value string) *string { return &value }

func generatedEndpointPath(t *testing.T, id string) string {
	t.Helper()
	for _, endpoint := range generated.Endpoints {
		if endpoint.ID == id {
			return endpoint.Path
		}
	}
	t.Fatalf("generated endpoint %q is missing", id)
	return ""
}

func generatedReadClientSummary(t *testing.T, address, certificatePath, assertion string, session *http.Cookie) generated.ApiSummaryData {
	t.Helper()
	probe := filepath.Join("..", "..", "tooling", "testdata", "generated-read-client-probe.mjs")
	command := exec.Command("node", probe)
	command.Env = append(os.Environ(),
		"VSK_CONSOLE_TEST_BASE_URL=https://"+address,
		"VSK_CONSOLE_TEST_CERTIFICATE="+certificatePath,
		"VSK_CONSOLE_TEST_ASSERTION="+assertion,
		"VSK_CONSOLE_TEST_COOKIE="+BrowserSessionCookieName+"="+session.Value,
	)
	output, err := command.Output()
	if err != nil {
		t.Fatalf("generated read client probe failed: %v", err)
	}
	var summary generated.ApiSummaryData
	if err := json.Unmarshal(output, &summary); err != nil {
		t.Fatalf("generated read client returned invalid data: %v", err)
	}
	return summary
}

func consoleStackRequest(t *testing.T, method, target, assertion string, session *http.Cookie) *http.Request {
	t.Helper()
	var body *strings.Reader
	if method == http.MethodPost {
		body = strings.NewReader(`{"requestVersion":"1.0.0"}`)
	} else {
		body = strings.NewReader("")
	}
	request, err := http.NewRequest(method, target, body)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "console.example"
	request.Header.Set("Origin", "https://console.example")
	request.Header.Set("Cf-Access-Jwt-Assertion", assertion)
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/json")
	}
	if session != nil {
		request.AddCookie(session)
	}
	return request
}
