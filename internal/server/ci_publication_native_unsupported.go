//go:build !linux

package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func composeCIPublicationNative(_ context.Context, p serverconfig.Profile, _ string, _ *store.Store, _ *adapter.Registry) error {
	if len(p.CIPublicationBindings) != 0 {
		return serviceFailure("PREREQUISITE_BLOCKED")
	}
	return nil
}
