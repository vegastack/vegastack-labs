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

func registerHostDiscovery(app *api.Application, authority *store.Store, registry *adapter.Registry, declarations *change.Service, results *result.Factory, ownerUID uint32, nativeGates ...*store.GateRepository) error {
	repository := store.NewHostDiscoveryRepository(authority)
	borrower := hostDiscoveryCredentials{preloaded: newPreloadedDiscoveryKeyReader(ownerUID), targets: repository, references: store.NewCredentialRepository(authority), profiles: store.NewGateRepository(authority), resolvers: registry}
	service := &hostdiscovery.Service{Repository: repository, Collector: &collector.Collector{Borrower: borrower}}
	if err := api.RegisterHostDiscoveryOperations(app, api.HostDiscoveryOperations{Service: service, Targets: repository, Declarations: declarations, Results: results}); err != nil {
		return err
	}
	gates := store.NewGateRepository(authority)
	if len(nativeGates) == 1 && nativeGates[0] != nil {
		gates = nativeGates[0]
	}
	native := &nativeQualificationService{adapters: registry, authority: authority, targets: repository, borrower: borrower, gates: gates}
	return api.RegisterQualificationOperations(app, api.QualificationOperations{Service: native, Revisions: store.NewPlanRepository(authority), Declarations: declarations, Results: results})
}
