package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
)

func (o *Operations) DiagnoseMaintenance(ctx context.Context, path, id string) (localapi.TypedResponse[generated.MaintenanceDiagnosis], error) {
	c, p, e := o.controlClient(ctx, path)
	if e != nil {
		return localapi.TypedResponse[generated.MaintenanceDiagnosis]{}, e
	}
	return c.DiagnoseMaintenance(ctx, p, id)
}
func (o *Operations) DraftMaintenance(ctx context.Context, path string, q generated.MaintenanceDraftRequest) (localapi.TypedResponse[generated.DeclarationRevision], error) {
	c, p, e := o.controlClient(ctx, path)
	if e != nil {
		return localapi.TypedResponse[generated.DeclarationRevision]{}, e
	}
	return c.DraftMaintenance(ctx, p, q)
}
