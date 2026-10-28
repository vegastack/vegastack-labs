package localapi

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localtransport"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

func (c *client) OperationsStatus(ctx context.Context, p serverconfig.Profile, observe bool) (TypedResponse[generated.OperationsStatusData], error) {
	method, path, id := localtransport.MethodGet, "/api/v1/operations", "api.v1.operations.status"
	var request any
	if observe {
		method = localtransport.MethodPost
		path += "/observe"
		id = "api.v1.operations.observe"
		request = generated.OperationsObserveRequest{Schema: generated.SchemaIDOperationsObserveRequest, SchemaVersion: "1.0.0"}
	}
	return requestTyped(c, ctx, p, requestSpec{method, path, id, maxOperationResponseBodyBytes, operationTimeout, false}, request, func(d generated.OperationsStatusData, r generated.RunResult) bool {
		return validGateData(d, generated.SchemaIDOperationsStatusData) && d.StateRevision == r.StateRevision && d.RecoveryEpoch == r.RecoveryEpoch
	})
}
