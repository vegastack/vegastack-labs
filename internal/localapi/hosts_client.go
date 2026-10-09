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
		return validGateData(data, generated.SchemaIDHostDiscoverySubmission) && data.OriginalRequestDigest == hostRequestDigest(input) && o.TargetID == input.TargetID && o.TargetRevision == input.TargetRevision && o.RecoveryEpoch == input.RecoveryEpoch && o.StateRevision == r.StateRevision && o.RecoveryEpoch == r.RecoveryEpoch
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
		return validGateData(data, generated.SchemaIDManagedHost) && data.HostID == id && data.StateRevision <= r.StateRevision && data.RecoveryEpoch == r.RecoveryEpoch
	})
}

func (client *client) GetHostObservation(ctx context.Context, profile serverconfig.Profile, id string) (TypedResponse[generated.HostObservation], error) {
	if !validPathToken(id) {
		return TypedResponse[generated.HostObservation]{}, failure.New(generated.ErrorCodeInputInvalid, "observation-id", false)
	}
	return requestTyped(client, ctx, profile, requestSpec{localtransport.MethodGet, "/api/v1/host-observations/" + id, "api.v1.host-observations.get", maxOperationResponseBodyBytes, operationTimeout, false}, nil, func(data generated.HostObservation, r generated.RunResult) bool {
		return validGateData(data, generated.SchemaIDHostObservation) && data.ObservationID == id && data.StateRevision == r.StateRevision && data.RecoveryEpoch == r.RecoveryEpoch
	})
}
func (client *client) PrepareHostTarget(ctx context.Context, profile serverconfig.Profile, input generated.HostDiscoveryTargetDraftRequest) (TypedResponse[generated.HostDiscoveryTargetDraftSubmission], error) {
	if !validGateData(input, generated.SchemaIDHostDiscoveryTargetDraftRequest) {
		return TypedResponse[generated.HostDiscoveryTargetDraftSubmission]{}, failure.New(generated.ErrorCodeInputInvalid, "host-target", false)
	}
	raw, _ := json.Marshal(input)
	sum := sha256.Sum256(raw)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	id := "discovery-draft-" + digest[7:39]
	return requestTyped(client, ctx, profile, requestSpec{localtransport.MethodPost, "/api/v1/host-discovery-targets/draft", "api.v1.host-discovery-targets.draft", maxOperationResponseBodyBytes, operationTimeout, false}, input, func(data generated.HostDiscoveryTargetDraftSubmission, r generated.RunResult) bool {
		return validGateData(data, generated.SchemaIDHostDiscoveryTargetDraftSubmission) && data.DraftID == id && data.DeclarationID == id && data.ContentDigest == digest && data.RecoveryEpoch == input.Target.RecoveryEpoch && data.RecoveryEpoch == r.RecoveryEpoch && data.StateRevision == r.StateRevision && data.StateRevision >= input.ExpectedStateRevision
	})
}

func (client *client) SubmitHostAction(ctx context.Context, profile serverconfig.Profile, input generated.HostActionRequest) (TypedResponse[generated.HostActionSubmission], error) {
	if !validGateData(input, generated.SchemaIDHostActionRequest) {
		return TypedResponse[generated.HostActionSubmission]{}, failure.New(generated.ErrorCodeInputInvalid, "host-actions", false)
	}
	// Bind the original desired request separately from the server-rendered content.
	original, _ := json.Marshal(input)
	sum := sha256.Sum256(original)
	originalDigest := "sha256:" + hex.EncodeToString(sum[:])
	return requestTyped(client, ctx, profile, requestSpec{localtransport.MethodPost, "/api/v1/host-actions/draft", "api.v1.host-actions.draft", maxOperationResponseBodyBytes, operationTimeout, false}, input, func(data generated.HostActionSubmission, r generated.RunResult) bool {
		if !validGateData(data, generated.SchemaIDHostActionSubmission) {
			return false
		}
		id := "host-action-" + data.ContentDigest[7:39]
		return data.OriginalRequestDigest == originalDigest && data.DraftID == id && data.DeclarationID == id && data.RecoveryEpoch == input.RecoveryEpoch && data.RecoveryEpoch == r.RecoveryEpoch && data.StateRevision == r.StateRevision && data.StateRevision >= input.ExpectedStateRevision
	})
}

func (client *client) SubmitHostAccess(ctx context.Context, profile serverconfig.Profile, input generated.HostAccessDraftRequest) (TypedResponse[generated.HostActionSubmission], error) {
	if !validGateData(input, generated.SchemaIDHostAccessDraftRequest) {
		return TypedResponse[generated.HostActionSubmission]{}, failure.New(generated.ErrorCodeInputInvalid, "host-access", false)
	}
	// Bind the original desired request separately from the server-rendered content.
	original, _ := json.Marshal(input)
	sum := sha256.Sum256(original)
	originalDigest := "sha256:" + hex.EncodeToString(sum[:])
	return requestTyped(client, ctx, profile, requestSpec{localtransport.MethodPost, "/api/v1/host-access/draft", "api.v1.host-access.draft", maxOperationResponseBodyBytes, operationTimeout, false}, input, func(data generated.HostActionSubmission, r generated.RunResult) bool {
		if !validGateData(data, generated.SchemaIDHostActionSubmission) {
			return false
		}
		id := "host-access-" + data.ContentDigest[7:39]
		return data.OriginalRequestDigest == originalDigest && data.DraftID == id && data.DeclarationID == id && data.RecoveryEpoch == input.Subject.RecoveryEpoch && data.RecoveryEpoch == r.RecoveryEpoch && data.StateRevision == r.StateRevision && data.StateRevision >= input.Subject.ExpectedStateRevision
	})
}

func (client *client) PrepareHostReplacement(ctx context.Context, profile serverconfig.Profile, input generated.HostReplacementRequest) (TypedResponse[generated.HostReplacementSubmission], error) {
	raw, err := json.Marshal(input)
	if err != nil || len(raw) > 32768 || !validGateData(input, generated.SchemaIDHostReplacementRequest) {
		return TypedResponse[generated.HostReplacementSubmission]{}, failure.New(generated.ErrorCodeInputInvalid, "host-replacement", false)
	}
	sum := sha256.Sum256(raw)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	id := "host-replacement-" + digest[7:39]
	return requestTyped(client, ctx, profile, requestSpec{localtransport.MethodPost, "/api/v1/host-replacements", "api.v1.host-replacements.create", maxOperationResponseBodyBytes, operationTimeout, false}, input, func(data generated.HostReplacementSubmission, r generated.RunResult) bool {
		return validGateData(data, generated.SchemaIDHostReplacementSubmission) && data.ReplacementID == input.ReplacementID && data.DraftID == id && data.DeclarationID == id && data.ContentDigest == digest && data.StateRevision == r.StateRevision && data.StateRevision >= input.ExpectedStateRevision && data.RecoveryEpoch == r.RecoveryEpoch && data.RecoveryEpoch == input.RecoveryEpoch
	})
}
func (client *client) GetHostReplacement(ctx context.Context, profile serverconfig.Profile, id string) (TypedResponse[generated.HostReplacementState], error) {
	if !validPathToken(id) {
		return TypedResponse[generated.HostReplacementState]{}, failure.New(generated.ErrorCodeInputInvalid, "replacement-id", false)
	}
	return requestTyped(client, ctx, profile, requestSpec{localtransport.MethodGet, "/api/v1/host-replacements/" + id, "api.v1.host-replacements.get", maxOperationResponseBodyBytes, operationTimeout, false}, nil, func(data generated.HostReplacementState, r generated.RunResult) bool {
		return validGateData(data, generated.SchemaIDHostReplacementState) && data.ReplacementID == id && data.StateRevision == r.StateRevision && data.RecoveryEpoch == r.RecoveryEpoch
	})
}

func hostRequestDigest(input any) string {
	raw, _ := json.Marshal(input)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
