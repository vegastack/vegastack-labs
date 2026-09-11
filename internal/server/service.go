// Package server owns the single foreground control-service lifecycle and HTTP router.
package server

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

const productionIntegrityInterval = 250 * time.Millisecond
const remoteRequestLimit = 64

var forbiddenIdentityHeaders = []string{"X-VSK-Principal", "X-VSK-UID", "X-VSK-GID", "X-VSK-Role"}

type Config struct {
	Profile           serverconfig.Profile
	Application       Application
	Results           *result.Factory
	ListenerFactory   localapi.ListenerFactory
	PlatformProbe     PlatformProbe
	IntegrityInterval time.Duration
	Remote            *RemoteConfig
}

type RemoteConfig struct {
	Authenticator    *BrowserAuthenticator
	Console          http.Handler
	ListenConfig     RemoteListenConfig
	ListenerFactory  RemoteListenerFactory
	PreflightFailure RemoteReadReason
}

type service struct {
	config Config
	mu     sync.RWMutex
	state  LifecycleState
	remote remoteReadHealth
}

type RemoteReadState string
type RemoteReadReason string

const (
	RemoteReadDisabled    RemoteReadState = "disabled"
	RemoteReadStarting    RemoteReadState = "starting"
	RemoteReadReady       RemoteReadState = "ready"
	RemoteReadUnavailable RemoteReadState = "unavailable"

	RemoteReadReasonNone                 RemoteReadReason = "none"
	RemoteReadReasonPreflightUnavailable RemoteReadReason = "preflight-unavailable"
	RemoteReadReasonAuthenticationFailed RemoteReadReason = "authentication-unavailable"
	RemoteReadReasonListenerUnavailable  RemoteReadReason = "listener-unavailable"
	RemoteReadReasonServeFailed          RemoteReadReason = "serve-failed"
)

type remoteReadHealth struct {
	state  RemoteReadState
	reason RemoteReadReason
}

func validRemoteReadHealth(health remoteReadHealth) bool {
	switch health.state {
	case RemoteReadDisabled, RemoteReadStarting, RemoteReadReady:
		return health.reason == RemoteReadReasonNone
	case RemoteReadUnavailable:
		return health.reason == RemoteReadReasonPreflightUnavailable ||
			health.reason == RemoteReadReasonAuthenticationFailed ||
			health.reason == RemoteReadReasonListenerUnavailable ||
			health.reason == RemoteReadReasonServeFailed
	default:
		return false
	}
}

func New(config Config) (Service, error) {
	if config.Application == nil || config.Results == nil || config.Profile.ShutdownGrace != 5*time.Second {
		return nil, failure.New("INPUT_INVALID", "control-service", false)
	}
	if config.ListenerFactory == nil {
		config.ListenerFactory = localapi.Listen
	}
	if config.PlatformProbe == nil {
		config.PlatformProbe = NewRuntimePlatformProbe()
	}
	if config.IntegrityInterval <= 0 {
		config.IntegrityInterval = productionIntegrityInterval
	}
	if config.Profile.RemoteRead.Enabled != (config.Remote != nil) {
		return nil, failure.New("INPUT_INVALID", "remote-control-service", false)
	}
	remote := remoteReadHealth{state: RemoteReadDisabled, reason: RemoteReadReasonNone}
	if config.Remote != nil {
		remote = remoteReadHealth{state: RemoteReadStarting, reason: RemoteReadReasonNone}
		if config.Remote.PreflightFailure != "" {
			if !validRemoteReadHealth(remoteReadHealth{state: RemoteReadUnavailable, reason: config.Remote.PreflightFailure}) {
				return nil, failure.New("INPUT_INVALID", "remote-control-service", false)
			}
		} else if config.Remote.Authenticator == nil || config.Remote.Console == nil {
			return nil, failure.New("INPUT_INVALID", "remote-control-service", false)
		}
		if config.Remote.ListenerFactory == nil {
			config.Remote.ListenerFactory = RemoteListen
		}
	}
	return &service{config: config, state: StateStarting, remote: remote}, nil
}

func (service *service) Run(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return failure.New(generated.ErrorCodeInterrupted, "control-service", false)
	}
	platform, err := service.config.PlatformProbe.Current(ctx)
	if err != nil {
		return stableOr(err, generated.ErrorCodeUnsupportedPlatform, "server-platform")
	}
	if !supportedPlatform(platform) {
		return failure.New(generated.ErrorCodeUnsupportedPlatform, "server-platform", false)
	}
	resolver, err := identity.NewLocalPrincipalResolver(service.config.Profile.PrincipalBindings)
	if err != nil {
		return failure.New(generated.ErrorCodeInputInvalid, "principal-bindings", false)
	}
	listener, err := service.config.ListenerFactory(ctx, localapi.ListenConfig{Profile: service.config.Profile, Resolver: resolver})
	if err != nil {
		return stableOr(err, generated.ErrorCodeExecutionFailed, "control-service")
	}

	httpServer := &http.Server{
		Handler: service,
		ConnContext: func(ctx context.Context, connection net.Conn) context.Context {
			authenticated, ok := connection.(localapi.AuthenticatedConn)
			if !ok {
				return ctx
			}
			return identity.WithVerifiedPrincipal(ctx, authenticated.Principal())
		},
		ReadHeaderTimeout: 3 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- httpServer.Serve(listener) }()

	if err := service.config.Application.Start(ctx); err != nil {
		shutdownErr := service.shutdown(listener, httpServer)
		if ctx.Err() != nil {
			return failure.New(generated.ErrorCodeInterrupted, "control-service", false)
		}
		if shutdownErr != nil {
			return shutdownErr
		}
		return stableOr(err, generated.ErrorCodeExecutionFailed, "application-start")
	}
	health, err := service.config.Application.Health(ctx)
	if err != nil {
		_ = service.shutdown(listener, httpServer)
		return stableOr(err, generated.ErrorCodeIntegrityFailure, "application-health")
	}
	if health.SafeMode {
		service.setState(StateSafeMode)
	} else {
		service.setState(StateReady)
	}

	remoteListener, remoteServer, remoteDone := service.startRemote(ctx)

	ticker := time.NewTicker(service.config.IntegrityInterval)
	defer ticker.Stop()
	var terminal error
selectLoop:
	for {
		select {
		case <-ctx.Done():
			break selectLoop
		case serveErr := <-serveDone:
			if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) && !errors.Is(serveErr, net.ErrClosed) {
				terminal = failure.New(generated.ErrorCodeExecutionFailed, "control-service", false)
			}
			break selectLoop
		case remoteErr := <-remoteDone:
			if remoteErr != nil && !errors.Is(remoteErr, http.ErrServerClosed) && !errors.Is(remoteErr, net.ErrClosed) {
				service.setRemote(RemoteReadUnavailable, RemoteReadReasonServeFailed)
			} else if ctx.Err() == nil {
				service.setRemote(RemoteReadUnavailable, RemoteReadReasonServeFailed)
			}
			remoteDone = nil
		case <-ticker.C:
			if err := listener.CheckPath(); err != nil {
				terminal = stableOr(err, generated.ErrorCodeIntegrityFailure, "control-socket")
				break selectLoop
			}
		}
	}
	service.setState(StateStopping)
	if shutdownErr := service.shutdownAll(listener, httpServer, remoteListener, remoteServer); terminal == nil {
		terminal = shutdownErr
	}
	return terminal
}

func (service *service) startRemote(ctx context.Context) (net.Listener, *http.Server, <-chan error) {
	remote := service.config.Remote
	if remote == nil {
		return nil, nil, nil
	}
	if remote.PreflightFailure != "" {
		service.setRemote(RemoteReadUnavailable, remote.PreflightFailure)
		return nil, nil, nil
	}
	if err := remote.Authenticator.Start(ctx); err != nil {
		service.setRemote(RemoteReadUnavailable, RemoteReadReasonAuthenticationFailed)
		return nil, nil, nil
	}
	handler, err := NewBrowserHandler(service, remote.Console, remote.Authenticator)
	if err != nil {
		service.setRemote(RemoteReadUnavailable, RemoteReadReasonPreflightUnavailable)
		return nil, nil, nil
	}
	listener, err := remote.ListenerFactory(ctx, remote.ListenConfig)
	if err != nil {
		service.setRemote(RemoteReadUnavailable, RemoteReadReasonListenerUnavailable)
		return nil, nil, nil
	}
	httpServer := &http.Server{Handler: newRemoteAdmissionHandler(handler, remoteRequestLimit), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 * 1024}
	done := make(chan error, 1)
	go func() { done <- httpServer.Serve(listener) }()
	service.setRemote(RemoteReadReady, RemoteReadReasonNone)
	return listener, httpServer, done
}

type remoteAdmissionHandler struct {
	next  http.Handler
	slots chan struct{}
}

func newRemoteAdmissionHandler(next http.Handler, limit int) http.Handler {
	return &remoteAdmissionHandler{next: next, slots: make(chan struct{}, limit)}
}

func (handler *remoteAdmissionHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	select {
	case handler.slots <- struct{}{}:
		defer func() { <-handler.slots }()
		handler.next.ServeHTTP(writer, request)
	default:
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("Retry-After", "1")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		http.Error(writer, "REMOTE_CAPACITY_UNAVAILABLE", http.StatusTooManyRequests)
	}
}

func (service *service) shutdown(listener localapi.Listener, httpServer *http.Server) error {
	return service.shutdownAll(listener, httpServer, nil, nil)
}

func (service *service) shutdownAll(listener localapi.Listener, httpServer *http.Server, remoteListener net.Listener, remoteServer *http.Server) error {
	_ = listener.Close()
	if remoteListener != nil {
		_ = remoteListener.Close()
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), service.config.Profile.ShutdownGrace)
	defer cancel()
	var terminal error
	if err := httpServer.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
		_ = httpServer.Close()
		terminal = failure.New(generated.ErrorCodeExecutionFailed, "control-service-drain", false)
	}
	if remoteServer != nil {
		if err := remoteServer.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			_ = remoteServer.Close()
			if terminal == nil {
				terminal = failure.New(generated.ErrorCodeExecutionFailed, "remote-service-drain", false)
			}
		}
	}
	applicationDone := make(chan error, 1)
	go func() { applicationDone <- service.config.Application.Shutdown(shutdownCtx) }()
	select {
	case err := <-applicationDone:
		if err != nil && terminal == nil {
			terminal = stableOr(err, generated.ErrorCodeExecutionFailed, "application-shutdown")
		}
	case <-shutdownCtx.Done():
		if terminal == nil {
			terminal = failure.New(generated.ErrorCodeExecutionFailed, "application-shutdown", false)
		}
	}
	if err := listener.CheckPath(); err != nil && terminal == nil {
		terminal = stableOr(err, generated.ErrorCodeIntegrityFailure, "control-socket")
	}
	if err := listener.Cleanup(); err != nil && terminal == nil {
		terminal = stableOr(err, generated.ErrorCodeIntegrityFailure, "control-socket")
	}
	return terminal
}

func (service *service) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	for _, header := range forbiddenIdentityHeaders {
		if request.Header.Values(header) != nil {
			service.writeFailure(writer, request, http.StatusUnauthorized, generated.ErrorCodeAuthenticationRequired, "identity-header", false)
			return
		}
	}
	principal, ok := identity.PrincipalFromContext(request.Context())
	if !ok {
		if request.URL.Path == "/api/v1/session" {
			if _, verified := identity.RemoteIdentityFromContext(request.Context()); verified {
				service.config.Application.ServeHTTP(writer, request)
				return
			}
		}
		service.writeFailure(writer, request, http.StatusUnauthorized, generated.ErrorCodeAuthenticationRequired, "local-peer", false)
		return
	}
	if request.URL.Path != "/api/v1/health" {
		service.config.Application.ServeHTTP(writer, request)
		return
	}
	if request.Method != http.MethodGet {
		service.writeFailure(writer, request, http.StatusMethodNotAllowed, generated.ErrorCodeInputInvalid, "method", false)
		return
	}
	if authorizer, ok := service.config.Application.(HealthAuthorizer); ok {
		if err := authorizer.AuthorizeHealth(request.Context(), principal); err != nil {
			service.writeFailure(writer, request, http.StatusForbidden, generated.ErrorCodeAuthorizationDenied, "health", false)
			return
		}
	}
	if request.Body != nil {
		content, err := io.ReadAll(io.LimitReader(request.Body, 1))
		if err != nil || len(content) != 0 {
			service.writeFailure(writer, request, http.StatusBadRequest, generated.ErrorCodeInputInvalid, "request-body", false)
			return
		}
	}
	health, err := service.config.Application.Health(request.Context())
	if err != nil {
		service.writeFailure(writer, request, http.StatusServiceUnavailable, generated.ErrorCodeIntegrityFailure, "application-health", false)
		return
	}
	state := service.currentState()
	if (state == StateReady || state == StateSafeMode) && health.SafeMode {
		state = StateSafeMode
	}
	remote := service.currentRemote()
	status := generated.ServerStatusData{
		State: string(state), ReadAvailable: state == StateReady || state == StateSafeMode,
		MutationAvailable: false, RecoveryEpoch: health.RecoveryEpoch, StateRevision: health.StateRevision,
		RemoteReadState: string(remote.state), RemoteReadReason: string(remote.reason),
	}
	envelope, err := service.config.Results.Success(generated.CommandNameServerStatus, health.RecoveryEpoch, health.StateRevision, status)
	if err != nil {
		http.Error(writer, "INTEGRITY_FAILURE", http.StatusInternalServerError)
		return
	}
	writeEnvelope(writer, http.StatusOK, envelope)
}

func (service *service) writeFailure(writer http.ResponseWriter, request *http.Request, statusCode int, code, target string, retryable bool) {
	var health ApplicationHealth
	if _, authenticated := identity.PrincipalFromContext(request.Context()); authenticated && code != generated.ErrorCodeAuthorizationDenied && code != generated.ErrorCodeAuthenticationRequired {
		health, _ = service.config.Application.Health(request.Context())
	}
	remote := service.currentRemote()
	data := generated.ServerStatusData{State: string(service.currentState()), RecoveryEpoch: health.RecoveryEpoch, StateRevision: health.StateRevision, RemoteReadState: string(remote.state), RemoteReadReason: string(remote.reason)}
	envelope, err := service.config.Results.Failure(generated.CommandNameServerStatus, generated.RunStatusFailed, code, target, retryable, health.RecoveryEpoch, health.StateRevision, data)
	if err != nil {
		http.Error(writer, "INTEGRITY_FAILURE", http.StatusInternalServerError)
		return
	}
	writeEnvelope(writer, statusCode, envelope)
}

func writeEnvelope(writer http.ResponseWriter, statusCode int, envelope generated.RunResult) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(statusCode)
	_ = result.Encode(writer, envelope)
}

func (service *service) setState(state LifecycleState) {
	service.mu.Lock()
	service.state = state
	service.mu.Unlock()
}

func (service *service) currentState() LifecycleState {
	service.mu.RLock()
	defer service.mu.RUnlock()
	return service.state
}

func (service *service) setRemote(state RemoteReadState, reason RemoteReadReason) {
	health := remoteReadHealth{state: state, reason: reason}
	if !validRemoteReadHealth(health) {
		health = remoteReadHealth{state: RemoteReadUnavailable, reason: RemoteReadReasonPreflightUnavailable}
	}
	service.mu.Lock()
	service.remote = health
	service.mu.Unlock()
}

func (service *service) currentRemote() remoteReadHealth {
	service.mu.RLock()
	defer service.mu.RUnlock()
	if service.remote.state == "" {
		return remoteReadHealth{state: RemoteReadDisabled, reason: RemoteReadReasonNone}
	}
	return service.remote
}

func stableOr(err error, code, target string) error {
	if stable, ok := failure.As(err); ok {
		return stable
	}
	return failure.New(code, target, false)
}
