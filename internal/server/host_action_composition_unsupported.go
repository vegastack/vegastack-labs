//go:build !linux

package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func composeHostActions(_ context.Context, p serverconfig.Profile, _ string, _ *store.Store, _ *adapter.Registry) (func(), error) {
	if p.HostActionSignerPath != "" {
		return func() {}, actionFailure()
	}
	return func() {}, nil
}
