package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
)

func (o *Operations) GetHostingLifecycle(ctx context.Context, path, id string) (localapi.TypedResponse[generated.HostingLifecycleRecord], error) {
	c, p, e := o.controlClient(ctx, path)
	if e != nil {
		return localapi.TypedResponse[generated.HostingLifecycleRecord]{}, e
	}
	return c.GetHostingLifecycle(ctx, p, id)
}
func (o *Operations) DraftHostingLifecycle(ctx context.Context, path string, in generated.HostingLifecycleDraftRequest) (localapi.TypedResponse[generated.DeclarationRevision], error) {
	c, p, e := o.controlClient(ctx, path)
	if e != nil {
		return localapi.TypedResponse[generated.DeclarationRevision]{}, e
	}
	return c.DraftHostingLifecycle(ctx, p, in)
}
