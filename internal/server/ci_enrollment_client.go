package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
)

func (o *Operations) ListCIEnrollments(ctx context.Context, path, after string, limit int) (localapi.TypedResponse[generated.CiEnrollmentList], error) {
	c, p, err := o.controlClient(ctx, path)
	if err != nil {
		return localapi.TypedResponse[generated.CiEnrollmentList]{}, err
	}
	return c.ListCIEnrollments(ctx, p, after, limit)
}
func (o *Operations) GetCIEnrollment(ctx context.Context, path, id string) (localapi.TypedResponse[generated.CiEnrollmentRecord], error) {
	c, p, err := o.controlClient(ctx, path)
	if err != nil {
		return localapi.TypedResponse[generated.CiEnrollmentRecord]{}, err
	}
	return c.GetCIEnrollment(ctx, p, id)
}
func (o *Operations) DraftCIEnrollment(ctx context.Context, path string, input generated.CiEnrollmentDraftRequest) (localapi.TypedResponse[generated.DeclarationRevision], error) {
	c, p, err := o.controlClient(ctx, path)
	if err != nil {
		return localapi.TypedResponse[generated.DeclarationRevision]{}, err
	}
	return c.DraftCIEnrollment(ctx, p, input)
}
