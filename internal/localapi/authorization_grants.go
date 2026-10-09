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

func (client *client) DraftAuthorizationGrants(ctx context.Context, profile serverconfig.Profile, input generated.AuthorizationGrantBatchRequest) (TypedResponse[generated.DeclarationRevision], error) {
	raw, err := json.Marshal(input)
	if err != nil || len(raw) > 32768 || !validGateData(input, generated.SchemaIDAuthorizationGrantBatchRequest) {
		return TypedResponse[generated.DeclarationRevision]{}, failure.New(generated.ErrorCodeInputInvalid, "grant-batch", false)
	}
	return requestTyped(client, ctx, profile, requestSpec{localtransport.MethodPost, "/api/v1/authorization/grant-batches", "api.v1.authorization.grant-batches.create", maxOperationResponseBodyBytes, operationTimeout, true}, input, func(d generated.DeclarationRevision, r generated.RunResult) bool {
		sum := sha256.Sum256([]byte(input.PrincipalID))
		expectedID := "authorization-policy-" + hex.EncodeToString(sum[:16])
		if len(d.Operations) != 1 {
			return false
		}
		op := d.Operations[0]
		return validGateData(d, generated.SchemaIDDeclarationRevision) && d.DeclarationID == expectedID && d.DeclarationType == "authorization.policy" && len(d.Extensions) == 0 && op.Sequence == 1 && op.OperationID == "grant-batch" && op.OperationType == "identity.change" && op.AdapterID == "core.authorization" && op.TargetID == input.PrincipalID && op.InputDigest == hostRequestDigest(input) && op.ArtifactDigest == hostRequestDigest("core.authorization@1") && !op.Idempotent && op.OffsiteRunSpec == nil && d.AuthorizationGrantBatch != nil && hostRequestDigest(d.AuthorizationGrantBatch) == hostRequestDigest(input) && d.Status == "draft" && d.Revision == input.ExpectedDeclarationRevision+1 && d.StateRevision == input.ExpectedStateRevision+1 && d.StateRevision == r.StateRevision && d.RecoveryEpoch == input.RecoveryEpoch && d.RecoveryEpoch == r.RecoveryEpoch
	})
}
