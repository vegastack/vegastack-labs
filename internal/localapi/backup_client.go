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

func (client *client) BackupStatus(ctx context.Context, profile serverconfig.Profile) (TypedResponse[generated.BackupStatusData], error) {
	return requestTyped(client, ctx, profile, requestSpec{localtransport.MethodGet, "/api/v1/backups/status", "api.v1.backups.status", maxOperationResponseBodyBytes, statusTimeout, false}, nil, func(data generated.BackupStatusData, result generated.RunResult) bool {
		raw, err := json.Marshal(data)
		return err == nil && generated.ValidateContractJSON(generated.SchemaIDBackupStatusData, raw, generated.ContractExact) == nil && data.RecoveryEpoch == result.RecoveryEpoch
	})
}

func (client *client) RunBackup(ctx context.Context, profile serverconfig.Profile, input generated.BackupRunRequest) (TypedResponse[generated.BackupJob], error) {
	return client.backupMutation(ctx, profile, "/api/v1/backups/run", "api.v1.backups.run", generated.SchemaIDBackupRunRequest, input, "", input.RecoveryEpoch)
}

func (client *client) VerifyBackup(ctx context.Context, profile serverconfig.Profile, input generated.BackupVerifyRequest) (TypedResponse[generated.BackupJob], error) {
	if !validPathToken(input.JobID) {
		return TypedResponse[generated.BackupJob]{}, failure.New(generated.ErrorCodeInputInvalid, "backup-job", false)
	}
	return client.backupMutation(ctx, profile, "/api/v1/backups/"+input.JobID+"/verify", "api.v1.backups.verify", generated.SchemaIDBackupVerifyRequest, input, input.JobID, input.RecoveryEpoch)
}

func (client *client) backupMutation(ctx context.Context, profile serverconfig.Profile, path, operation, schema string, input any, expectedJob string, epoch int64) (TypedResponse[generated.BackupJob], error) {
	var zero TypedResponse[generated.BackupJob]
	raw, err := json.Marshal(input)
	if err != nil || generated.ValidateContractJSON(schema, raw, generated.ContractExact) != nil {
		return zero, failure.New(generated.ErrorCodeInputInvalid, "backup-request", false)
	}
	return requestTyped(client, ctx, profile, requestSpec{localtransport.MethodPost, path, operation, maxOperationResponseBodyBytes, operationTimeout, true}, input, func(data generated.BackupJob, result generated.RunResult) bool {
		raw, err := json.Marshal(data)
		return err == nil && generated.ValidateContractJSON(generated.SchemaIDBackupJob, raw, generated.ContractExact) == nil && data.RecoveryEpoch == epoch && result.RecoveryEpoch == epoch && (expectedJob == "" || data.JobID == expectedJob)
	})
}
