package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
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
	shutdownErr    error
	shutdownCalled atomic.Bool
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
