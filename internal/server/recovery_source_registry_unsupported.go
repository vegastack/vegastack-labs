//go:build !linux

package server

import (
	"context"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func registerProductionRecoveryCredentialResolver(context.Context, *adapter.Registry, *store.CredentialRepository, *store.GateRepository, uint32) error {
	return nil
}
