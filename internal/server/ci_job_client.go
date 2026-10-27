package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
)

func (o *Operations) DraftCIJob(ctx context.Context, path string, in generated.CiJobDraftRequest) (localapi.TypedResponse[generated.DeclarationRevision], error) {
	c, p, e := o.controlClient(ctx, path)
	if e != nil {
		return localapi.TypedResponse[generated.DeclarationRevision]{}, e
	}
	return c.DraftCIJob(ctx, p, in)
}
