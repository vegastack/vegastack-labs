package localapi

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localtransport"
	"github.com/vegastack/vegastack-labs/internal/runprotocol"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

// ApplyBound preserves the ordinary execute route and uncertainty handling,
// while refusing a changed plan before sending an effectful request.
func (c *client) ApplyBound(ctx context.Context, p serverconfig.Profile, in generated.PlanReferenceRequest) (TypedResponse[generated.RunPresentation], error) {
	var zero TypedResponse[generated.RunPresentation]
	if !validGateData(in, generated.SchemaIDPlanReferenceRequest) || len(in.Extensions) != 0 {
		return zero, failure.New(generated.ErrorCodeInputInvalid, "bound-plan", false)
	}
	current, err := c.getPlan(ctx, p, in.PlanID)
	if err != nil {
		return zero, err
	}
	if current.ExitCode != 0 {
		return remapResponse[generated.RunPresentation](current), nil
	}
	if current.Data.PlanID != in.PlanID || current.Data.PlanDigest != in.PlanDigest || current.Data.Binding.RecoveryEpoch != in.RecoveryEpoch {
		return zero, failure.New(generated.ErrorCodePlanStale, "bound-plan", false)
	}
	id := runprotocol.ID(in.PlanID, in.IdempotencyKey)
	valid := func(d generated.RunPresentation, r generated.RunResult) bool {
		return validRunPresentation(d, r) && d.Run.RunID == id && d.Run.PlanID == in.PlanID && d.Run.PlanDigest == in.PlanDigest && d.Run.RecoveryEpoch == in.RecoveryEpoch
	}
	response, err := requestTyped(c, ctx, p, requestSpec{localtransport.MethodPost, "/api/v1/plans/" + in.PlanID + "/execute", "api.v1.plans.execute", maxOperationResponseBodyBytes, operationTimeout, true}, in, valid)
	if err == nil {
		return response, nil
	}
	inspected, inspectErr := c.InspectRun(context.WithoutCancel(ctx), p, id)
	if inspectErr == nil && inspected.ExitCode == 0 && valid(inspected.Data, inspected.Result) {
		return inspected, nil
	}
	return zero, NewUncertainRunError(id, err)
}
