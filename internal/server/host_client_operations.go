package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
)

func (operations *Operations) DiscoverHost(ctx context.Context, configPath string, input generated.HostDiscoveryRequest) (localapi.TypedResponse[generated.HostDiscoverySubmission], error) {
	client, profile, err := operations.controlClient(ctx, configPath)
	if err != nil {
		return localapi.TypedResponse[generated.HostDiscoverySubmission]{}, err
	}
	return client.DiscoverHost(ctx, profile, input)
}
func (operations *Operations) SubmitHostAdoption(ctx context.Context, configPath string, input generated.HostAdoptionRequest) (localapi.TypedResponse[generated.HostAdoptionSubmission], error) {
	client, profile, err := operations.controlClient(ctx, configPath)
	if err != nil {
		return localapi.TypedResponse[generated.HostAdoptionSubmission]{}, err
	}
	return client.SubmitHostAdoption(ctx, profile, input)
}
func (operations *Operations) GetManagedHost(ctx context.Context, configPath string, input string) (localapi.TypedResponse[generated.ManagedHost], error) {
	client, profile, err := operations.controlClient(ctx, configPath)
	if err != nil {
		return localapi.TypedResponse[generated.ManagedHost]{}, err
	}
	return client.GetManagedHost(ctx, profile, input)
}
