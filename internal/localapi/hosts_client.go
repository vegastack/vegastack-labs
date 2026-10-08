package localapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localtransport"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

func (client *client) DiscoverHost(ctx context.Context, profile serverconfig.Profile, input generated.HostDiscoveryRequest) (TypedResponse[generated.HostDiscoverySubmission], error) {
	if !validGateData(input, generated.SchemaIDHostDiscoveryRequest) {
		return TypedResponse[generated.HostDiscoverySubmission]{}, failure.New(generated.ErrorCodeInputInvalid, "host-discovery", false)
	}
	return requestTyped(client, ctx, profile, requestSpec{localtransport.MethodPost, "/api/v1/host-observations", "api.v1.host-observations.create", maxOperationResponseBodyBytes, operationTimeout, false}, input, func(data generated.HostDiscoverySubmission, r generated.RunResult) bool {
		o := data.Observation
		return validGateData(data, generated.SchemaIDHostDiscoverySubmission) && o.TargetID == input.TargetID && o.TargetRevision == input.TargetRevision && o.RecoveryEpoch == input.RecoveryEpoch && o.StateRevision == r.StateRevision && o.RecoveryEpoch == r.RecoveryEpoch
	})
}
func (client *client) SubmitHostAdoption(ctx context.Context, profile serverconfig.Profile, input generated.HostAdoptionRequest) (TypedResponse[generated.HostAdoptionSubmission], error) {
	if !validGateData(input, generated.SchemaIDHostAdoptionRequest) {
		return TypedResponse[generated.HostAdoptionSubmission]{}, failure.New(generated.ErrorCodeInputInvalid, "host-adoption", false)
	}
	raw, _ := json.Marshal(input)
	sum := sha256.Sum256(raw)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	id := "host-adoption-" + digest[7:39]
	return requestTyped(client, ctx, profile, requestSpec{localtransport.MethodPost, "/api/v1/host-adoptions/draft", "api.v1.host-adoptions.draft", maxOperationResponseBodyBytes, operationTimeout, false}, input, func(data generated.HostAdoptionSubmission, r generated.RunResult) bool {
		return validGateData(data, generated.SchemaIDHostAdoptionSubmission) && data.ContentDigest == digest && data.DraftID == id && data.DeclarationID == id && data.StateRevision == r.StateRevision && data.RecoveryEpoch == r.RecoveryEpoch && data.RecoveryEpoch == input.RecoveryEpoch
	})
}
func (client *client) GetManagedHost(ctx context.Context, profile serverconfig.Profile, id string) (TypedResponse[generated.ManagedHost], error) {
	if !validPathToken(id) {
		return TypedResponse[generated.ManagedHost]{}, failure.New(generated.ErrorCodeInputInvalid, "host-id", false)
	}
	return requestTyped(client, ctx, profile, requestSpec{localtransport.MethodGet, "/api/v1/hosts/" + id, "api.v1.hosts.get", maxOperationResponseBodyBytes, operationTimeout, false}, nil, func(data generated.ManagedHost, r generated.RunResult) bool {
		return validGateData(data, generated.SchemaIDManagedHost) && data.HostID == id && data.StateRevision == r.StateRevision && data.RecoveryEpoch == r.RecoveryEpoch
	})
}
