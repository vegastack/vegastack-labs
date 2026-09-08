package server

import (
	"context"
	"net/http"
)

type LifecycleState string

const (
	StateStarting LifecycleState = "starting"
	StateReady    LifecycleState = "ready"
	StateSafeMode LifecycleState = "safe-mode"
	StateStopping LifecycleState = "stopping"
)

type ApplicationHealth struct {
	SafeMode      bool
	RecoveryEpoch int64
	StateRevision int64
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
