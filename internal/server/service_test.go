package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

type staticPlatformProbe struct {
	platform Platform
	err      error
}

func (probe staticPlatformProbe) Current(context.Context) (Platform, error) {
	return probe.platform, probe.err
}

type testApplication struct {
	startBlock     chan struct{}
	startCalled    chan struct{}
	health         ApplicationHealth
	startErr       error
	healthErr      error
	healthCalls    atomic.Int32
	shutdownErr    error
	shutdownCalled atomic.Bool
}

type healthAuthorizedApplication struct {
	testApplication
	err error
}

func (application *healthAuthorizedApplication) AuthorizeHealth(context.Context, identity.Principal) error {
	return application.err
}

func (application *testApplication) Start(ctx context.Context) error {
	if application.startCalled != nil {
		close(application.startCalled)
	}
	if application.startBlock != nil {
		select {
		case <-application.startBlock:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return application.startErr
}
func (application *testApplication) Health(context.Context) (ApplicationHealth, error) {
	application.healthCalls.Add(1)
	return application.health, application.healthErr
}
func (application *testApplication) ServeHTTP(writer http.ResponseWriter, _ *http.Request) {
	http.NotFound(writer, nil)
}
func (application *testApplication) Shutdown(context.Context) error {
	application.shutdownCalled.Store(true)
	return application.shutdownErr
}

type serverTestAuthConn struct {
	net.Conn
	principal identity.Principal
}

func (connection *serverTestAuthConn) Principal() identity.Principal { return connection.principal }

type testListener struct {
	net.Listener
	principal identity.Principal
	auth      bool
	checkErr  atomic.Value
	once      sync.Once
}

type delayedCloseListener struct {
	acceptStarted chan struct{}
	closed        chan struct{}
	release       chan struct{}
	closeCount    atomic.Int32
}

func newDelayedCloseListener() *delayedCloseListener {
	return &delayedCloseListener{
		acceptStarted: make(chan struct{}),
		closed:        make(chan struct{}),
		release:       make(chan struct{}),
	}
}

func (listener *delayedCloseListener) Accept() (net.Conn, error) {
	close(listener.acceptStarted)
	<-listener.closed
	<-listener.release
	return nil, net.ErrClosed
}

func (listener *delayedCloseListener) Close() error {
	if listener.closeCount.Add(1) == 1 {
		close(listener.closed)
		return nil
	}
	select {
	case <-listener.release:
	default:
		close(listener.release)
	}
	return net.ErrClosed
}

func (*delayedCloseListener) Addr() net.Addr   { return &net.TCPAddr{} }
func (*delayedCloseListener) CheckPath() error { return nil }
func (*delayedCloseListener) Cleanup() error   { return nil }

func newTestListener(t *testing.T, auth bool) *testListener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return &testListener{Listener: listener, auth: auth, principal: identity.Principal{ID: "principal.test", Method: identity.LocalOSPeerMethod}}
}
func (listener *testListener) Accept() (net.Conn, error) {
	connection, err := listener.Listener.Accept()
	if err != nil || !listener.auth {
		return connection, err
	}
	return &serverTestAuthConn{Conn: connection, principal: listener.principal}, nil
}
func (listener *testListener) CheckPath() error {
	if value := listener.checkErr.Load(); value != nil {
		return value.(error)
	}
	return nil
}
func (listener *testListener) Cleanup() error {
	listener.once.Do(func() { _ = listener.Listener.Close() })
	return listener.CheckPath()
}

func testResultFactory() *result.Factory {
	return result.NewFactory(result.BuildInfo{ToolVersion: "0.2.0-test", ReleaseBuildID: "build-test"}, func() (string, error) { return "request-test", nil })
}

func testServerProfile() serverconfig.Profile {
	return serverconfig.Profile{
		ShutdownGrace:     5 * time.Second,
		PrincipalBindings: []identity.Binding{{UID: 1, PrincipalID: "principal.test"}},
	}
}

func testSupportedPlatform() Platform {
	return Platform{OS: "linux", Architecture: "amd64", Distribution: "debian", Major: 13}
}

func TestRemoteAdmissionLimitFailsClosed(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	handler := newRemoteAdmissionHandler(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		writer.WriteHeader(http.StatusNoContent)
	}), 1)
	firstDone := make(chan struct{})
	go func() {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "https://console.example/", nil))
		close(firstDone)
	}()
	<-started
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://console.example/", nil))
	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") != "1" {
		t.Fatalf("saturated remote response = %d, retry = %q", response.Code, response.Header().Get("Retry-After"))
	}
	close(release)
	<-firstDone
}

func TestRemoteReadHealthAllowsOnlyGeneratedStateReasonPairs(t *testing.T) {
	valid := []remoteReadHealth{
		{RemoteReadDisabled, RemoteReadReasonNone},
		{RemoteReadStarting, RemoteReadReasonNone},
		{RemoteReadReady, RemoteReadReasonNone},
		{RemoteReadUnavailable, RemoteReadReasonPreflightUnavailable},
		{RemoteReadUnavailable, RemoteReadReasonAuthenticationFailed},
		{RemoteReadUnavailable, RemoteReadReasonListenerUnavailable},
		{RemoteReadUnavailable, RemoteReadReasonServeFailed},
	}
	for _, health := range valid {
		if !validRemoteReadHealth(health) {
			t.Fatalf("valid remote health rejected: %#v", health)
		}
	}
	for _, health := range []remoteReadHealth{{"ready", "serve-failed"}, {"unknown", "none"}, {"unavailable", "none"}} {
		if validRemoteReadHealth(health) {
			t.Fatalf("invalid remote health accepted: %#v", health)
		}
	}
}

func TestShutdownToleratesExpectedHTTPListenerDoubleClose(t *testing.T) {
	listener := newDelayedCloseListener()
	httpServer := &http.Server{Handler: http.NotFoundHandler()}
	serveDone := make(chan error, 1)
	go func() { serveDone <- httpServer.Serve(listener) }()
	select {
	case <-listener.acceptStarted:
	case <-time.After(time.Second):
		t.Fatal("Serve() did not enter Accept")
	}

	service := &service{config: Config{
		Profile:     testServerProfile(),
		Application: &testApplication{},
	}}
	shutdownDone := make(chan error, 1)
	go func() { shutdownDone <- service.shutdown(listener, httpServer) }()
	select {
	case err := <-shutdownDone:
		if err != nil {
			t.Fatalf("shutdown = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown did not finish")
	}
	select {
	case err := <-serveDone:
		if !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("Serve() = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve() did not finish")
	}
	if got := listener.closeCount.Load(); got != 2 {
		t.Fatalf("listener Close() calls = %d, want 2", got)
	}
}

func TestServiceReportsAuthenticatedHealthAndRejectsSpoofHeaders(t *testing.T) {
	listener := newTestListener(t, true)
	application := &testApplication{health: ApplicationHealth{RecoveryEpoch: 7, StateRevision: 42}}
	service, err := New(Config{
		Profile: testServerProfile(), Application: application, Results: testResultFactory(),
		ListenerFactory: func(context.Context, localapi.ListenConfig) (localapi.Listener, error) { return listener, nil },
		PlatformProbe:   staticPlatformProbe{platform: testSupportedPlatform()}, IntegrityInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx) }()
	client := &http.Client{Timeout: time.Second}
	var response *http.Response
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		response, err = client.Get("http://" + listener.Addr().String() + "/api/v1/health")
		if err == nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	var envelope generated.RunResult
	if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	var status generated.ServerStatusData
	if err := json.Unmarshal(envelope.Data, &status); err != nil || status.State != "ready" || !status.ReadAvailable || status.MutationAvailable || status.RecoveryEpoch != 7 || status.StateRevision != 42 {
		t.Fatalf("health = %#v, %v", status, err)
	}
	request, _ := http.NewRequest(http.MethodGet, "http://"+listener.Addr().String()+"/api/v1/health", nil)
	request.Header.Set("X-VSK-Principal", "forged")
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("spoof response = %d", response.StatusCode)
	}
	_ = response.Body.Close()
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run() after cancel = %v", err)
	}
	if !application.shutdownCalled.Load() {
		t.Fatal("Application.Shutdown() was not called")
	}
}

func TestRemoteBindFailureLeavesLocalControlAvailable(t *testing.T) {
	listener := newTestListener(t, true)
	profile := testServerProfile()
	profile.RemoteRead.Enabled = true
	authenticator, _, _ := newBrowserAuthFixture(t)
	service, err := New(Config{
		Profile: profile, Application: &testApplication{health: ApplicationHealth{RecoveryEpoch: 7, StateRevision: 42}}, Results: testResultFactory(),
		ListenerFactory: func(context.Context, localapi.ListenConfig) (localapi.Listener, error) { return listener, nil },
		PlatformProbe:   staticPlatformProbe{platform: testSupportedPlatform()}, IntegrityInterval: 10 * time.Millisecond,
		Remote: &RemoteConfig{
			Authenticator: authenticator,
			Console:       testConsoleHandler(t),
			ListenConfig:  RemoteListenConfig{Address: "127.0.0.1:8443", CertificatePath: "/private/cert", PrivateKeyPath: "/private/key"},
			ListenerFactory: func(context.Context, RemoteListenConfig) (net.Listener, error) {
				return nil, errors.New("address-in-use private detail")
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx) }()
	client := &http.Client{Timeout: time.Second}
	var status generated.ServerStatusData
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		response, requestErr := client.Get("http://" + listener.Addr().String() + "/api/v1/health")
		if requestErr == nil {
			var envelope generated.RunResult
			if json.NewDecoder(response.Body).Decode(&envelope) == nil && json.Unmarshal(envelope.Data, &status) == nil && status.RemoteReadState == "unavailable" {
				_ = response.Body.Close()
				break
			}
			_ = response.Body.Close()
		}
		time.Sleep(time.Millisecond)
	}
	if status.State != "ready" || status.RemoteReadState != "unavailable" || status.RemoteReadReason != "listener-unavailable" {
		t.Fatalf("health = %#v", status)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run() after remote failure = %v", err)
	}
}

func TestServiceAuthenticatesBeforeReadingBody(t *testing.T) {
	listener := newTestListener(t, false)
	service, err := New(Config{
		Profile: testServerProfile(), Application: &testApplication{}, Results: testResultFactory(),
		ListenerFactory: func(context.Context, localapi.ListenConfig) (localapi.Listener, error) { return listener, nil },
		PlatformProbe:   staticPlatformProbe{platform: testSupportedPlatform()}, IntegrityInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx) }()
	response, err := (&http.Client{Timeout: time.Second}).Post("http://"+listener.Addr().String()+"/api/v1/health", "application/json", io.NopCloser(strings.NewReader("private-body")))
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d", response.StatusCode)
	}
	_ = response.Body.Close()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestServiceUnauthenticatedFailureDoesNotProbeOrDiscloseHealth(t *testing.T) {
	application := &testApplication{health: ApplicationHealth{RecoveryEpoch: 7, StateRevision: 42}}
	service := &service{
		config: Config{Application: application, Results: testResultFactory()},
		state:  StateReady,
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	response := httptest.NewRecorder()
	service.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", response.Code)
	}
	if calls := application.healthCalls.Load(); calls != 0 {
		t.Fatalf("unauthenticated request invoked Application.Health %d times", calls)
	}
	var envelope generated.RunResult
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	var status generated.ServerStatusData
	if err := json.Unmarshal(envelope.Data, &status); err != nil {
		t.Fatal(err)
	}
	if status.RecoveryEpoch != 0 || status.StateRevision != 0 || status.ReadAvailable || status.MutationAvailable {
		t.Fatalf("unauthenticated status = %#v", status)
	}
}

func TestServiceHealthGrantDenialDoesNotProbeOrDiscloseHealth(t *testing.T) {
	application := &healthAuthorizedApplication{testApplication: testApplication{health: ApplicationHealth{RecoveryEpoch: 7, StateRevision: 42}}, err: failure.New(generated.ErrorCodeAuthorizationDenied, "read", false)}
	service := &service{config: Config{Application: application, Results: testResultFactory()}, state: StateReady}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	request = request.WithContext(identity.WithVerifiedPrincipal(request.Context(), identity.Principal{ID: "principal.test", Method: identity.LocalOSPeerMethod}))
	response := httptest.NewRecorder()
	service.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || application.healthCalls.Load() != 0 {
		t.Fatalf("status/health calls = %d/%d", response.Code, application.healthCalls.Load())
	}
	var envelope generated.RunResult
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	var status generated.ServerStatusData
	if err := json.Unmarshal(envelope.Data, &status); err != nil {
		t.Fatal(err)
	}
	if status.RecoveryEpoch != 0 || status.StateRevision != 0 || status.ReadAvailable || status.MutationAvailable {
		t.Fatalf("denial disclosed health: %#v", status)
	}
}

func TestServiceRejectsUnsupportedPlatformBeforeListening(t *testing.T) {
	called := false
	service, err := New(Config{
		Profile: testServerProfile(), Application: &testApplication{}, Results: testResultFactory(),
		ListenerFactory: func(context.Context, localapi.ListenConfig) (localapi.Listener, error) {
			called = true
			return nil, errors.New("called")
		},
		PlatformProbe: staticPlatformProbe{platform: Platform{OS: "darwin", Architecture: "arm64"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = service.Run(context.Background())
	stable, ok := failure.As(err)
	if !ok || stable.Code != generated.ErrorCodeUnsupportedPlatform || called {
		t.Fatalf("Run() = %v, listener called=%t", err, called)
	}
}

func TestServiceStopsOnSocketIntegrityLoss(t *testing.T) {
	listener := newTestListener(t, true)
	service, err := New(Config{
		Profile: testServerProfile(), Application: &testApplication{}, Results: testResultFactory(),
		ListenerFactory: func(context.Context, localapi.ListenConfig) (localapi.Listener, error) { return listener, nil },
		PlatformProbe:   staticPlatformProbe{platform: testSupportedPlatform()}, IntegrityInterval: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- service.Run(context.Background()) }()
	time.Sleep(10 * time.Millisecond)
	listener.checkErr.Store(failure.New("INTEGRITY_FAILURE", "control-socket", false))
	select {
	case err := <-done:
		stable, ok := failure.As(err)
		if !ok || stable.Code != "INTEGRITY_FAILURE" {
			t.Fatalf("Run() = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("integrity monitor did not stop service")
	}
}
