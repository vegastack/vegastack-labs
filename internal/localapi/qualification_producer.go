package localapi

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/localtransport"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

func (c *client) LookupNativeProducerReference(ctx context.Context, p serverconfig.Profile, in generated.NativeProducerLookupRequest) (TypedResponse[generated.NativeProducerLookupData], error) {
	if !validGateData(in, generated.SchemaIDNativeProducerLookupRequest) {
		return TypedResponse[generated.NativeProducerLookupData]{}, failure.New(generated.ErrorCodeInputInvalid, "native-producer", false)
	}
	return requestTyped(c, ctx, p, requestSpec{localtransport.MethodPost, "/api/v1/qualification/native/producer", "api.v1.qualification.producer", maxOperationResponseBodyBytes, operationTimeout, false}, in, func(d generated.NativeProducerLookupData, r generated.RunResult) bool {
		ref := d.ProducerReference
		protocol := in.ScenarioID == "action-replay" || in.ScenarioID == "action-concurrency"
		return validGateData(d, generated.SchemaIDNativeProducerLookupData) && ref.ScenarioID == in.ScenarioID && ref.HostID == in.HostID && ref.PlanID == in.PlanID && ref.PlanDigest == in.PlanDigest && ref.RunID == in.RunID && ref.StepID == in.StepID && r.RecoveryEpoch == in.RecoveryEpoch && protocol == (d.ActionBundle != nil) && (d.ActionBundle == nil || hostaction.NativeProducerBundleMatches(in, ref, *d.ActionBundle))
	})
}
