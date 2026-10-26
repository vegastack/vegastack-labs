package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
)

func (o *Operations) ListServices(ctx context.Context, path, after string, limit int) (localapi.TypedResponse[generated.ServiceList], error) {
	c, p, err := o.controlClient(ctx, path)
	if err != nil {
		return localapi.TypedResponse[generated.ServiceList]{}, err
	}
	return c.ListServices(ctx, p, after, limit)
}
func (o *Operations) GetService(ctx context.Context, path, id string) (localapi.TypedResponse[generated.ServiceRecord], error) {
	c, p, err := o.controlClient(ctx, path)
	if err != nil {
		return localapi.TypedResponse[generated.ServiceRecord]{}, err
	}
	return c.GetService(ctx, p, id)
}
func (o *Operations) ObserveService(ctx context.Context, path, id string) (localapi.TypedResponse[generated.ServiceObservation], error) {
	c, p, err := o.controlClient(ctx, path)
	if err != nil {
		return localapi.TypedResponse[generated.ServiceObservation]{}, err
	}
	return c.ObserveService(ctx, p, id)
}
func (o *Operations) DraftServiceImport(ctx context.Context, path string, input generated.ServiceImportDraftRequest) (localapi.TypedResponse[generated.DeclarationRevision], error) {
	c, p, err := o.controlClient(ctx, path)
	if err != nil {
		return localapi.TypedResponse[generated.DeclarationRevision]{}, err
	}
	return c.DraftServiceImport(ctx, p, input)
}
