package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
)

func (o *Operations) DraftIngress(ctx context.Context, path string, q generated.IngressDraftRequest) (localapi.TypedResponse[generated.IngressDraftSubmission], error) {
	c, p, e := o.controlClient(ctx, path)
	if e != nil {
		return localapi.TypedResponse[generated.IngressDraftSubmission]{}, e
	}
	return c.DraftIngress(ctx, p, q)
}
func (o *Operations) IngressStatus(ctx context.Context, path, id string) (localapi.TypedResponse[generated.IngressStatusData], error) {
	c, p, e := o.controlClient(ctx, path)
	if e != nil {
		return localapi.TypedResponse[generated.IngressStatusData]{}, e
	}
	return c.IngressStatus(ctx, p, id)
}

func (o *Operations) ObserveIngress(ctx context.Context, path string, q generated.IngressDraftRequest) (localapi.TypedResponse[generated.IngressStatusData], error) {
	c, p, e := o.controlClient(ctx, path)
	if e != nil {
		return localapi.TypedResponse[generated.IngressStatusData]{}, e
	}
	return c.ObserveIngress(ctx, p, q)
}

func (o *Operations) SubmitIngressRolloutEvidence(ctx context.Context, path string, q generated.IngressRolloutEvidenceRequest) (localapi.TypedResponse[generated.IngressStatusData], error) {
	c, p, e := o.controlClient(ctx, path)
	if e != nil {
		return localapi.TypedResponse[generated.IngressStatusData]{}, e
	}
	return c.SubmitIngressRolloutEvidence(ctx, p, q)
}

func (o *Operations) DraftIngressPilotEvidence(ctx context.Context, path string, q generated.IngressPilotEvidenceRequest) (localapi.TypedResponse[generated.GateEvidenceSubmission], error) {
	c, p, e := o.controlClient(ctx, path)
	if e != nil {
		return localapi.TypedResponse[generated.GateEvidenceSubmission]{}, e
	}
	return c.DraftIngressPilotEvidence(ctx, p, q)
}
