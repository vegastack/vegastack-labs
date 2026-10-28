package localapi

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localtransport"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

func (c *client) NotificationReadiness(ctx context.Context, p serverconfig.Profile, q generated.NotificationReadinessRequest) (TypedResponse[generated.DeclarationRevision], error) {
	if !validGateData(q, generated.SchemaIDNotificationReadinessRequest) {
		return TypedResponse[generated.DeclarationRevision]{}, failure.New(generated.ErrorCodeInputInvalid, "notification-readiness-request", false)
	}
	return requestTyped(c, ctx, p, requestSpec{localtransport.MethodPost, "/api/v1/operations/notification-readiness", "api.v1.operations.notification-readiness", maxOperationResponseBodyBytes, operationTimeout, true}, q, func(d generated.DeclarationRevision, r generated.RunResult) bool {
		return validGateData(d, generated.SchemaIDDeclarationRevision) && d.StateRevision == r.StateRevision && d.RecoveryEpoch == r.RecoveryEpoch
	})
}
