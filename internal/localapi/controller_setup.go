package localapi

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localtransport"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

func (c *client) ClaimControllerSetup(ctx context.Context, p serverconfig.Profile, q generated.ControllerSetupClaimRequest) (TypedResponse[generated.ControllerSetupClaim], error) {
	if !validGateData(q, generated.SchemaIDControllerSetupClaimRequest) || p.ConstrainedSSH != nil {
		return TypedResponse[generated.ControllerSetupClaim]{}, failure.New(generated.ErrorCodeAuthorizationDenied, "controller-setup-local", false)
	}
	return requestTyped(c, ctx, p, requestSpec{localtransport.MethodPost, "/api/v1/controller-setup/claim", "api.v1.controller-setup.claim", maxOperationResponseBodyBytes, operationTimeout, true}, q, func(d generated.ControllerSetupClaim, r generated.RunResult) bool {
		return validGateData(d, generated.SchemaIDControllerSetupClaim) && d.Run.StateRevision == r.StateRevision && d.Run.RecoveryEpoch == r.RecoveryEpoch && d.Plan.PlanID == q.Reference.PlanID && d.Plan.PlanDigest == q.Reference.PlanDigest
	})
}
func (c *client) SubmitControllerSetupReceipt(ctx context.Context, p serverconfig.Profile, q generated.ControllerSetupReceiptRequest) (TypedResponse[generated.Run], error) {
	if !validGateData(q, generated.SchemaIDControllerSetupReceiptRequest) || p.ConstrainedSSH != nil {
		return TypedResponse[generated.Run]{}, failure.New(generated.ErrorCodeAuthorizationDenied, "controller-setup-local", false)
	}
	return requestTyped(c, ctx, p, requestSpec{localtransport.MethodPost, "/api/v1/controller-setup/receipt", "api.v1.controller-setup.receipt", maxOperationResponseBodyBytes, operationTimeout, true}, q, func(d generated.Run, r generated.RunResult) bool {
		return validGateData(d, generated.SchemaIDRun) && d.RunID == q.RunID && d.StateRevision == r.StateRevision && d.RecoveryEpoch == r.RecoveryEpoch
	})
}

func (c *client) PrepareControllerSetupRecovery(ctx context.Context, p serverconfig.Profile, q generated.ControllerSetupRecoveryRequest) (TypedResponse[generated.ControllerSetupRecoveryData], error) {
	if !validGateData(q, generated.SchemaIDControllerSetupRecoveryRequest) || p.ConstrainedSSH != nil {
		return TypedResponse[generated.ControllerSetupRecoveryData]{}, failure.New(generated.ErrorCodeAuthorizationDenied, "controller-setup-local", false)
	}
	return requestTyped(c, ctx, p, requestSpec{localtransport.MethodPost, "/api/v1/controller-setup/recovery", "api.v1.controller-setup.recovery", maxOperationResponseBodyBytes, operationTimeout, true}, q, func(d generated.ControllerSetupRecoveryData, r generated.RunResult) bool {
		return validGateData(d, generated.SchemaIDControllerSetupRecoveryData) && d.StateRevision == r.StateRevision && d.RecoveryEpoch == r.RecoveryEpoch
	})
}
