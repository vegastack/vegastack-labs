package localapi

import (
	"context"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localtransport"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

func (client *client) CreateCredentialLifecycleDraft(ctx context.Context, profile serverconfig.Profile, input generated.CredentialLifecycleRequest) (TypedResponse[generated.CredentialLifecycleSubmission], error) {
	var zero TypedResponse[generated.CredentialLifecycleSubmission]
	if !validGateData(input, generated.SchemaIDCredentialLifecycleRequest) || input.TargetDigest == "" || input.TargetDigest != credentialref.LifecycleTargetDigest(input) {
		return zero, failure.New(generated.ErrorCodeInputInvalid, "credential-lifecycle-request", false)
	}
	return requestTyped(client, ctx, profile, requestSpec{localtransport.MethodPost, "/api/v1/credential-lifecycle-drafts", "api.v1.credential-lifecycle-drafts.create", maxOperationResponseBodyBytes, operationTimeout, true}, input, func(data generated.CredentialLifecycleSubmission, result generated.RunResult) bool {
		return validGateData(data, generated.SchemaIDCredentialLifecycleSubmission) && data.ReferenceID == input.ReferenceID && data.Action == input.Action && data.Status == "draft" && data.StateRevision == input.ExpectedStateRevision+2 && data.RecoveryEpoch == input.RecoveryEpoch && data.StateRevision == result.StateRevision && data.RecoveryEpoch == result.RecoveryEpoch
	})
}
