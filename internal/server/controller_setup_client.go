package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
)

func (o *Operations) ClaimControllerSetup(ctx context.Context, path string, q generated.ControllerSetupClaimRequest) (localapi.TypedResponse[generated.ControllerSetupClaim], error) {
	c, p, e := o.controlClient(ctx, path)
	if e != nil {
		return localapi.TypedResponse[generated.ControllerSetupClaim]{}, e
	}
	return c.ClaimControllerSetup(ctx, p, q)
}
func (o *Operations) SubmitControllerSetupReceipt(ctx context.Context, path string, q generated.ControllerSetupReceiptRequest) (localapi.TypedResponse[generated.Run], error) {
	c, p, e := o.controlClient(ctx, path)
	if e != nil {
		return localapi.TypedResponse[generated.Run]{}, e
	}
	return c.SubmitControllerSetupReceipt(ctx, p, q)
}
