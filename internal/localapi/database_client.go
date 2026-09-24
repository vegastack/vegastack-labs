package localapi

import (
	"context"
	"encoding/json"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localtransport"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

func (client *client) RunDatabaseBackup(ctx context.Context, profile serverconfig.Profile, input generated.BackupRunRequest) (TypedResponse[generated.BackupJob], error) {
	return databaseRequest(client, ctx, profile, "/api/v1/database/backups", "api.v1.database-backups.create", generated.SchemaIDBackupRunRequest, input, func(data generated.BackupJob, result generated.RunResult) bool {
		raw, err := json.Marshal(data)
		return err == nil && generated.ValidateContractJSON(generated.SchemaIDBackupJob, raw, generated.ContractExact) == nil && data.RecoveryEpoch == result.RecoveryEpoch
	})
}

func (client *client) VerifyDatabase(ctx context.Context, profile serverconfig.Profile, input generated.BackupVerifyRequest) (TypedResponse[generated.BackupJob], error) {
	return databaseRequest(client, ctx, profile, "/api/v1/database/verifications", "api.v1.database-verifications.create", generated.SchemaIDBackupVerifyRequest, input, func(data generated.BackupJob, result generated.RunResult) bool {
		raw, err := json.Marshal(data)
		return err == nil && generated.ValidateContractJSON(generated.SchemaIDBackupJob, raw, generated.ContractExact) == nil && data.RecoveryEpoch == result.RecoveryEpoch
	})
}

func (client *client) PlanDatabaseRestore(ctx context.Context, profile serverconfig.Profile, input generated.RestoreRequest) (TypedResponse[generated.RestoreBinding], error) {
	return databaseRequest(client, ctx, profile, "/api/v1/database/restores", "api.v1.database-restores.create", generated.SchemaIDRestoreRequest, input, func(data generated.RestoreBinding, result generated.RunResult) bool {
		raw, err := json.Marshal(data)
		return err == nil && generated.ValidateContractJSON(generated.SchemaIDRestoreBinding, raw, generated.ContractExact) == nil && data.PointID == input.PointID && data.PriorRecoveryEpoch == result.RecoveryEpoch
	})
}

func (client *client) DraftDatabaseExport(ctx context.Context, profile serverconfig.Profile, input generated.DatabaseExportRequest) (TypedResponse[generated.DatabaseExportDraftSubmission], error) {
	return databaseRequest(client, ctx, profile, "/api/v1/database/exports", "api.v1.database-exports.create", generated.SchemaIDDatabaseExportRequest, input, func(data generated.DatabaseExportDraftSubmission, result generated.RunResult) bool {
		raw, err := json.Marshal(data)
		return err == nil && generated.ValidateContractJSON(generated.SchemaIDDatabaseExportDraftSubmission, raw, generated.ContractExact) == nil && data.ExportID == input.ExportID && data.Status == "draft" && data.StateRevision == result.StateRevision && data.RecoveryEpoch == result.RecoveryEpoch
	})
}

func databaseRequest[T any, I any](client *client, ctx context.Context, profile serverconfig.Profile, path, operation, schema string, input I, validate func(T, generated.RunResult) bool) (TypedResponse[T], error) {
	var zero TypedResponse[T]
	raw, err := json.Marshal(input)
	if err != nil || generated.ValidateContractJSON(schema, raw, generated.ContractExact) != nil {
		return zero, failure.New(generated.ErrorCodeInputInvalid, "database-operation-request", false)
	}
	return requestTyped(client, ctx, profile, requestSpec{localtransport.MethodPost, path, operation, maxOperationResponseBodyBytes, operationTimeout, true}, input, validate)
}
