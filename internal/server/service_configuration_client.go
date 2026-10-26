package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
)

func (o *Operations) GetServiceConfiguration(ctx context.Context, path, id string) (localapi.TypedResponse[generated.ServiceConfigurationStatus], error) {
	c, p, e := o.controlClient(ctx, path)
	if e != nil {
		return localapi.TypedResponse[generated.ServiceConfigurationStatus]{}, e
	}
	return c.GetServiceConfiguration(ctx, p, id)
}
