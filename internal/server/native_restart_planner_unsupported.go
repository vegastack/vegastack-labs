//go:build !linux

package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func composeNativeRestartPlanner(context.Context, string, uint32, *store.CredentialRepository) api.CredentialNativeRestartPlanner {
	return nil
}
