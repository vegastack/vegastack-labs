//go:build !linux

package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func composeManualPublicationNative(_ context.Context, p serverconfig.Profile, _ string, _ *store.Store, _ *adapter.Registry) error {
	if len(p.ManualPublicationBindings) != 0 {
		return serviceFailure("PREREQUISITE_BLOCKED")
	}
	return nil
}
