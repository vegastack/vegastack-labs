package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
)

func (o *Operations) DraftCIPublication(ctx context.Context, path string, in generated.CiPublicationDraftRequest) (localapi.TypedResponse[generated.DeclarationRevision], error) {
	c, p, e := o.controlClient(ctx, path)
	if e != nil {
		return localapi.TypedResponse[generated.DeclarationRevision]{}, e
	}
	return c.DraftCIPublication(ctx, p, in)
}
