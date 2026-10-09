package localapi

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localtransport"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

func (c *client) LookupNativeProducerReference(ctx context.Context, p serverconfig.Profile, in generated.NativeProducerLookupRequest) (TypedResponse[generated.NativeProducerReference], error) {
	if !validGateData(in, generated.SchemaIDNativeProducerLookupRequest) {
		return TypedResponse[generated.NativeProducerReference]{}, failure.New(generated.ErrorCodeInputInvalid, "native-producer", false)
	}
	return requestTyped(c, ctx, p, requestSpec{localtransport.MethodPost, "/api/v1/qualification/native/producer", "api.v1.qualification.producer", maxOperationResponseBodyBytes, operationTimeout, false}, in, func(d generated.NativeProducerReference, r generated.RunResult) bool {
		return validGateData(d, generated.SchemaIDNativeProducerReference) && d.ScenarioID == in.ScenarioID && d.HostID == in.HostID && d.PlanID == in.PlanID && d.PlanDigest == in.PlanDigest && d.RunID == in.RunID && d.StepID == in.StepID && r.RecoveryEpoch == in.RecoveryEpoch
	})
}
