package server

import (
	"context"
	"net/http"

	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/readmodel"
)

type LifecycleState string

const (
	StateStarting LifecycleState = "starting"
	StateReady    LifecycleState = "ready"
	StateSafeMode LifecycleState = "safe-mode"
	StateStopping LifecycleState = "stopping"
)

type ApplicationHealth = readmodel.ApplicationHealth

type HealthAuthorizer interface {
	AuthorizeHealth(context.Context, identity.Principal) error
}

type Application interface {
	Start(context.Context) error
	Health(context.Context) (ApplicationHealth, error)
	ServeHTTP(http.ResponseWriter, *http.Request)
	Shutdown(context.Context) error
}

type AuthorityHealth struct {
	SafeMode      bool
	RecoveryEpoch int64
	StateRevision int64
}

type StateAuthority interface {
	Health(context.Context) (AuthorityHealth, error)
	Close() error
}

type Service interface {
	Run(context.Context) error
}
