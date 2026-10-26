package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
)

func (o *Operations) GetServiceRecovery(ctx context.Context, path, id string) (localapi.TypedResponse[generated.ServiceRecoveryRecord], error) {
	c, p, e := o.controlClient(ctx, path)
	if e != nil {
		return localapi.TypedResponse[generated.ServiceRecoveryRecord]{}, e
	}
	return c.GetServiceRecovery(ctx, p, id)
}
func (o *Operations) DraftServiceRecovery(ctx context.Context, path string, in generated.ServiceRecoveryDraftRequest) (localapi.TypedResponse[generated.DeclarationRevision], error) {
	c, p, e := o.controlClient(ctx, path)
	if e != nil {
		return localapi.TypedResponse[generated.DeclarationRevision]{}, e
	}
	return c.DraftServiceRecovery(ctx, p, in)
}
