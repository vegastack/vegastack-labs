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
