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

func (operations *Operations) PrepareHostTarget(ctx context.Context, configPath string, input generated.HostDiscoveryTargetDraftRequest) (localapi.TypedResponse[generated.HostDiscoveryTargetDraftSubmission], error) {
	client, profile, err := operations.controlClient(ctx, configPath)
	if err != nil {
		return localapi.TypedResponse[generated.HostDiscoveryTargetDraftSubmission]{}, err
	}
	return client.PrepareHostTarget(ctx, profile, input)
}

func (operations *Operations) SubmitHostAction(ctx context.Context, configPath string, input generated.HostActionRequest) (localapi.TypedResponse[generated.HostActionSubmission], error) {
	client, profile, err := operations.controlClient(ctx, configPath)
	if err != nil {
		return localapi.TypedResponse[generated.HostActionSubmission]{}, err
	}
	return client.SubmitHostAction(ctx, profile, input)
}

func (operations *Operations) SubmitHostAccess(ctx context.Context, configPath string, input generated.HostAccessDraftRequest) (localapi.TypedResponse[generated.HostActionSubmission], error) {
	client, profile, err := operations.controlClient(ctx, configPath)
	if err != nil {
		return localapi.TypedResponse[generated.HostActionSubmission]{}, err
	}
	return client.SubmitHostAccess(ctx, profile, input)
}

func (operations *Operations) GetHostObservation(ctx context.Context, configPath string, input string) (localapi.TypedResponse[generated.HostObservation], error) {
	client, profile, err := operations.controlClient(ctx, configPath)
	if err != nil {
		return localapi.TypedResponse[generated.HostObservation]{}, err
	}
	return client.GetHostObservation(ctx, profile, input)
}

func (operations *Operations) PrepareHostReplacement(ctx context.Context, configPath string, input generated.HostReplacementRequest) (localapi.TypedResponse[generated.HostReplacementSubmission], error) {
	client, profile, err := operations.controlClient(ctx, configPath)
	if err != nil {
		return localapi.TypedResponse[generated.HostReplacementSubmission]{}, err
	}
	return client.PrepareHostReplacement(ctx, profile, input)
}
func (operations *Operations) GetHostReplacement(ctx context.Context, configPath string, id string) (localapi.TypedResponse[generated.HostReplacementState], error) {
	client, profile, err := operations.controlClient(ctx, configPath)
	if err != nil {
		return localapi.TypedResponse[generated.HostReplacementState]{}, err
	}
	return client.GetHostReplacement(ctx, profile, id)
}
