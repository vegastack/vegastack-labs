package localapi

import (
	"context"
	"encoding/json"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localtransport"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

// SubmitBackupPolicyDraft stores one inert canonical backup-policy draft over
// the local control socket and returns its opaque draft ID and digest.
func (client *client) SubmitBackupPolicyDraft(ctx context.Context, profile serverconfig.Profile, input generated.BackupPolicyDraftRequest) (TypedResponse[generated.BackupPolicyDraftSubmission], error) {
	var zero TypedResponse[generated.BackupPolicyDraftSubmission]
	raw, err := json.Marshal(input)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDBackupPolicyDraftRequest, raw, generated.ContractExact) != nil {
		return zero, failure.New(generated.ErrorCodeInputInvalid, "backup-policy-draft", false)
	}
	return requestTyped(client, ctx, profile, requestSpec{localtransport.MethodPost, "/api/v1/backups/policies/drafts", "api.v1.backup-policy-drafts.create", maxOperationResponseBodyBytes, operationTimeout, true}, input, func(data generated.BackupPolicyDraftSubmission, result generated.RunResult) bool {
		return data.Schema == generated.SchemaIDBackupPolicyDraftSubmission && data.PolicyDigest == input.TargetDigest && data.Status == "draft" && data.StateRevision == result.StateRevision && data.RecoveryEpoch == result.RecoveryEpoch
	})
}
