package localapi

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localtransport"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

// RequestPlanApproval requests the ordinary human acknowledgement. It cannot
// acknowledge a plan, choose an approver or replace the configured transport.
func (c *client) RequestPlanApproval(ctx context.Context, p serverconfig.Profile, in generated.PlanReferenceRequest) (TypedResponse[generated.ApprovalStatus], error) {
	if !validGateData(in, generated.SchemaIDPlanReferenceRequest) || len(in.Extensions) != 0 {
		return TypedResponse[generated.ApprovalStatus]{}, failure.New(generated.ErrorCodeInputInvalid, "approval-request", false)
	}
	return requestTyped(c, ctx, p, requestSpec{localtransport.MethodPost, "/api/v1/plans/" + in.PlanID + "/approval-request", "api.v1.plans.approval-request.create", maxOperationResponseBodyBytes, operationTimeout, true}, in, func(d generated.ApprovalStatus, r generated.RunResult) bool {
		return validApproval(d, r) && d.PlanID == in.PlanID && d.PlanDigest == in.PlanDigest && d.RecoveryEpoch == in.RecoveryEpoch
	})
}
func (c *client) GetPlanApproval(ctx context.Context, p serverconfig.Profile, id string) (TypedResponse[generated.ApprovalStatus], error) {
	if !validPathToken(id) {
		return TypedResponse[generated.ApprovalStatus]{}, failure.New(generated.ErrorCodeInputInvalid, "plan-id", false)
	}
	return requestTyped(c, ctx, p, requestSpec{localtransport.MethodGet, "/api/v1/plans/" + id + "/approval-status", "api.v1.plans.approval-status.get", maxOperationResponseBodyBytes, operationTimeout, false}, nil, func(d generated.ApprovalStatus, r generated.RunResult) bool {
		return validApproval(d, r) && d.PlanID == id
	})
}
func validApproval(d generated.ApprovalStatus, r generated.RunResult) bool {
	return validGateData(d, generated.SchemaIDApprovalStatus) && d.StateRevision == r.StateRevision && d.RecoveryEpoch == r.RecoveryEpoch
}
