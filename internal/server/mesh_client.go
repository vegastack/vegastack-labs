package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
)

func (o *Operations) DraftMesh(ctx context.Context, path string, q generated.MeshDraftRequest) (localapi.TypedResponse[generated.MeshDraftSubmission], error) {
	c, p, e := o.controlClient(ctx, path)
	if e != nil {
		return localapi.TypedResponse[generated.MeshDraftSubmission]{}, e
	}
	return c.DraftMesh(ctx, p, q)
}
func (o *Operations) MeshStatus(ctx context.Context, path, id string) (localapi.TypedResponse[generated.MeshStatusData], error) {
	c, p, e := o.controlClient(ctx, path)
	if e != nil {
		return localapi.TypedResponse[generated.MeshStatusData]{}, e
	}
	return c.MeshStatus(ctx, p, id)
}

func (o *Operations) ObserveMesh(ctx context.Context, path string, q generated.MeshDraftRequest) (localapi.TypedResponse[generated.MeshStatusData], error) {
	c, p, e := o.controlClient(ctx, path)
	if e != nil {
		return localapi.TypedResponse[generated.MeshStatusData]{}, e
	}
	return c.ObserveMesh(ctx, p, q)
}
