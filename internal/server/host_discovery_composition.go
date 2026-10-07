package server

import (
	"github.com/vegastack/vegastack-labs/internal/adapter"
	collector "github.com/vegastack/vegastack-labs/internal/adapter/hostdiscovery"
	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func registerHostDiscovery(app *api.Application, authority *store.Store, registry *adapter.Registry, declarations *change.Service, results *result.Factory) error {
	repository := store.NewHostDiscoveryRepository(authority)
	borrower := hostDiscoveryCredentials{targets: repository, references: store.NewCredentialRepository(authority), profiles: store.NewGateRepository(authority), resolvers: registry}
	service := &hostdiscovery.Service{Repository: repository, Collector: &collector.Collector{Borrower: borrower}}
	return api.RegisterHostDiscoveryOperations(app, api.HostDiscoveryOperations{Service: service, Targets: repository, Declarations: declarations, Results: results})
}
