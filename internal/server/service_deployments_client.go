package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
)

func (o *Operations) GetServiceDeployment(ctx context.Context, path, id string) (localapi.TypedResponse[generated.ServiceDeploymentRecord], error) {
	c, p, e := o.controlClient(ctx, path)
	if e != nil {
		return localapi.TypedResponse[generated.ServiceDeploymentRecord]{}, e
	}
	return c.GetServiceDeployment(ctx, p, id)
}
func (o *Operations) DraftServiceDeployment(ctx context.Context, path string, in generated.ServiceDeploymentDraftRequest) (localapi.TypedResponse[generated.DeclarationRevision], error) {
	c, p, e := o.controlClient(ctx, path)
	if e != nil {
		return localapi.TypedResponse[generated.DeclarationRevision]{}, e
	}
	return c.DraftServiceDeployment(ctx, p, in)
}
