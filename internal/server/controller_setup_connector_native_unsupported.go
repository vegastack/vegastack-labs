//go:build !linux

package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func observeControllerConnectorNative(context.Context, serverconfig.Profile, *store.Store, string, generated.Plan, generated.IngressChange) error {
	return actionFailure()
}
