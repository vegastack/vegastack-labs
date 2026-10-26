//go:build !linux

package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func composeIngressNative(context.Context, serverconfig.Profile, string, *store.Store, *adapter.Registry) error {
	return nil
}
