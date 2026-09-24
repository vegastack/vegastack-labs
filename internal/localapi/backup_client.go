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

func (client *client) SubmitBackupRetentionLockDraft(ctx context.Context, profile serverconfig.Profile, input generated.BackupRetentionLockDraftRequest) (TypedResponse[generated.BackupRetentionLockDraftSubmission], error) {
	var zero TypedResponse[generated.BackupRetentionLockDraftSubmission]
	raw, err := json.Marshal(input)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDBackupRetentionLockDraftRequest, raw, generated.ContractExact) != nil {
		return zero, failure.New(generated.ErrorCodeInputInvalid, "backup-retention-lock-draft", false)
	}
	return requestTyped(client, ctx, profile, requestSpec{localtransport.MethodPost, "/api/v1/backups/retention-locks/drafts", "api.v1.backup-retention-lock-drafts.create", maxOperationResponseBodyBytes, operationTimeout, true}, input, func(data generated.BackupRetentionLockDraftSubmission, result generated.RunResult) bool {
		return data.Schema == generated.SchemaIDBackupRetentionLockDraftSubmission && data.CatalogDigest == input.TargetDigest && data.Status == "draft" && data.StateRevision == result.StateRevision && data.RecoveryEpoch == result.RecoveryEpoch
	})
}

func (client *client) SubmitBackupRetirementDraft(ctx context.Context, profile serverconfig.Profile, input generated.BackupRetirementDraftRequest) (TypedResponse[generated.BackupRetirementDraftSubmission], error) {
	var zero TypedResponse[generated.BackupRetirementDraftSubmission]
	raw, err := json.Marshal(input)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDBackupRetirementDraftRequest, raw, generated.ContractExact) != nil {
		return zero, failure.New(generated.ErrorCodeInputInvalid, "backup-retirement-draft", false)
	}
	return requestTyped(client, ctx, profile, requestSpec{localtransport.MethodPost, "/api/v1/backups/retirements/drafts", "api.v1.backup-retirement-drafts.create", maxOperationResponseBodyBytes, operationTimeout, true}, input, func(data generated.BackupRetirementDraftSubmission, result generated.RunResult) bool {
		return data.Schema == generated.SchemaIDBackupRetirementDraftSubmission && data.SelectionDigest != "" && data.CredentialManifestDigest != "" && len(data.TargetPointIDs) > 0 && len(data.SurvivorPointIDs) > 0 && data.Status == "draft" && data.StateRevision == result.StateRevision && data.RecoveryEpoch == result.RecoveryEpoch
	})
}

func (client *client) StageBackupOffsiteRetirement(ctx context.Context, profile serverconfig.Profile, input generated.BackupOffsiteRetirementStageRequest) (TypedResponse[generated.BackupOffsiteRetirementStageSubmission], error) {
	var zero TypedResponse[generated.BackupOffsiteRetirementStageSubmission]
	raw, err := json.Marshal(input)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDBackupOffsiteRetirementStageRequest, raw, generated.ContractExact) != nil {
		return zero, failure.New(generated.ErrorCodeInputInvalid, "backup-offsite-retirement-stage", false)
	}
	return requestTyped(client, ctx, profile, requestSpec{localtransport.MethodPost, "/api/v1/backups/offsite-retirements/stage", "api.v1.backup-offsite-retirements.stage", maxOperationResponseBodyBytes, operationTimeout, true}, input, func(data generated.BackupOffsiteRetirementStageSubmission, result generated.RunResult) bool {
		return data.Schema == generated.SchemaIDBackupOffsiteRetirementStageSubmission && data.Status == "staged" && data.StateRevision == result.StateRevision && data.RecoveryEpoch == result.RecoveryEpoch
	})
}

func (client *client) DryRunBackupOffsiteRetirement(ctx context.Context, profile serverconfig.Profile, input generated.BackupOffsiteRetirementDryRunRequest) (TypedResponse[generated.BackupOffsiteRetirementDryRunData], error) {
	var zero TypedResponse[generated.BackupOffsiteRetirementDryRunData]
	raw, err := json.Marshal(input)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDBackupOffsiteRetirementDryRunRequest, raw, generated.ContractExact) != nil {
		return zero, failure.New(generated.ErrorCodeInputInvalid, "backup-offsite-retirement-dry-run", false)
	}
	return requestTyped(client, ctx, profile, requestSpec{localtransport.MethodPost, "/api/v1/backups/offsite-retirements/dry-run", "api.v1.backup-offsite-retirements.dry-run", maxOperationResponseBodyBytes, operationTimeout, true}, input, func(data generated.BackupOffsiteRetirementDryRunData, result generated.RunResult) bool {
		return data.Schema == generated.SchemaIDBackupOffsiteRetirementDryRunData && data.IntentDigest != "" && data.StateRevision == result.StateRevision && data.RecoveryEpoch == result.RecoveryEpoch
	})
}

func (client *client) BackupStatus(ctx context.Context, profile serverconfig.Profile) (TypedResponse[generated.BrowserBackupStatusData], error) {
	return requestTyped(client, ctx, profile, requestSpec{localtransport.MethodGet, "/api/v1/backups/status", "api.v1.backups.status", maxOperationResponseBodyBytes, statusTimeout, false}, nil, func(data generated.BrowserBackupStatusData, result generated.RunResult) bool {
		raw, err := json.Marshal(data)
		return err == nil && generated.ValidateContractJSON(generated.SchemaIDBrowserBackupStatusData, raw, generated.ContractExact) == nil && data.StateRevision == result.StateRevision && data.RecoveryEpoch == result.RecoveryEpoch
	})
}

func (client *client) RunBackup(ctx context.Context, profile serverconfig.Profile, input generated.BackupRunRequest) (TypedResponse[generated.BackupJob], error) {
	if !validPathToken(input.PolicyID) {
		return TypedResponse[generated.BackupJob]{}, failure.New(generated.ErrorCodeInputInvalid, "backup-policy", false)
	}
	return client.backupMutation(ctx, profile, "/api/v1/backup-policies/"+input.PolicyID+"/jobs", "api.v1.backup-jobs.create", generated.SchemaIDBackupRunRequest, input, "", input.RecoveryEpoch)
}

func (client *client) VerifyBackup(ctx context.Context, profile serverconfig.Profile, input generated.BackupVerifyRequest) (TypedResponse[generated.BackupJob], error) {
	if !validPathToken(input.PointID) {
		return TypedResponse[generated.BackupJob]{}, failure.New(generated.ErrorCodeInputInvalid, "recovery-point", false)
	}
	return client.backupMutation(ctx, profile, "/api/v1/recovery-points/"+input.PointID+"/verifications", "api.v1.backup-verifications.create", generated.SchemaIDBackupVerifyRequest, input, input.JobID, input.RecoveryEpoch)
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
