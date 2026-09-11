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

var forbiddenIdentityHeaders = []string{"X-VSK-Principal", "X-VSK-UID", "X-VSK-GID", "X-VSK-Role"}

type Config struct {
	Profile           serverconfig.Profile
	Application       Application
	Results           *result.Factory
	ListenerFactory   localapi.ListenerFactory
	PlatformProbe     PlatformProbe
	IntegrityInterval time.Duration
}

type service struct {
	config Config
	mu     sync.RWMutex
	state  LifecycleState
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
	return &service{config: config, state: StateStarting}, nil
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
		case <-ticker.C:
			if err := listener.CheckPath(); err != nil {
				terminal = stableOr(err, generated.ErrorCodeIntegrityFailure, "control-socket")
				break selectLoop
			}
		}
	}
	service.setState(StateStopping)
	if shutdownErr := service.shutdown(listener, httpServer); terminal == nil {
		terminal = shutdownErr
	}
	return terminal
}

func (service *service) shutdown(listener localapi.Listener, httpServer *http.Server) error {
	_ = listener.Close()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), service.config.Profile.ShutdownGrace)
	defer cancel()
	var terminal error
	if err := httpServer.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
		_ = httpServer.Close()
		terminal = failure.New(generated.ErrorCodeExecutionFailed, "control-service-drain", false)
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
	principal, ok := identity.PrincipalFromContext(request.Context())
	if !ok {
		service.writeFailure(writer, request, http.StatusUnauthorized, generated.ErrorCodeAuthenticationRequired, "local-peer", false)
		return
	}
	for _, header := range forbiddenIdentityHeaders {
		if request.Header.Values(header) != nil {
			service.writeFailure(writer, request, http.StatusUnauthorized, generated.ErrorCodeAuthenticationRequired, "identity-header", false)
			return
		}
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
	status := generated.ServerStatusData{
		State: string(state), ReadAvailable: state == StateReady || state == StateSafeMode,
		MutationAvailable: false, RecoveryEpoch: health.RecoveryEpoch, StateRevision: health.StateRevision,
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
	data := generated.ServerStatusData{State: string(service.currentState()), RecoveryEpoch: health.RecoveryEpoch, StateRevision: health.StateRevision}
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

func stableOr(err error, code, target string) error {
	if stable, ok := failure.As(err); ok {
		return stable
	}
	return failure.New(code, target, false)
}
