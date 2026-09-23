//go:build !linux

package server

import (
	"context"
	"errors"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/generated"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func composeR2RetirementCredentials(context.Context, serverconfig.Profile, *adapter.Registry, *store.GateRepository, *store.OffsiteRetirementRepository) (runengine.GateVerifier, error) {
	return nil, errors.New("r2 retirement credentials unsupported")
}

func NewLabsR2RetirementExecution(context.Context, serverconfig.Profile, *store.Store, generated.GateEvidence) (runengine.OffsiteRetirementExecution, error) {
	return nil, errors.New("r2 retirement requires linux")
}

func NewProductionOffsiteRetirementCatalogFactory() OffsiteRetirementCatalogFactory {
	return func(context.Context, serverconfig.Profile, *store.Store) (api.OffsiteRetirementCatalogSource, error) {
		return api.UnavailableOffsiteRetirementCatalogSource{}, nil
	}
}
