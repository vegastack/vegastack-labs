package cli

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func (app *App) runDatabaseOperation(ctx context.Context, mode outputMode, parsed parsedArguments) int {
	control, ok := app.control.(DatabaseControlOperations)
	if !ok || app.files == nil {
		return app.fail(mode, parsed.commandName(), generated.ErrorCodeIntegrityFailure, "database-control", generated.RunStatusFailed, false)
	}
	limit := int64(4096)
	if parsed.commandName() == generated.CommandNameDatabaseRestore {
		limit = 262144
	}
	raw, err := app.files.Read(ctx, parsed.Value(generated.FlagFile), limit)
	if err != nil {
		return app.failServer(mode, parsed.commandName(), err)
	}
	config := parsed.Value(generated.FlagConfig)
	switch parsed.commandName() {
	case generated.CommandNameDatabaseBackup:
		var input generated.BackupRunRequest
		if json.Unmarshal(raw, &input) != nil || generated.ValidateContractJSON(generated.SchemaIDBackupRunRequest, raw, generated.ContractExact) != nil {
			return app.fail(mode, parsed.commandName(), generated.ErrorCodeInputInvalid, "database-backup-contract", generated.RunStatusFailed, false)
		}
		response, callErr := control.RunDatabaseBackup(ctx, config, input)
		if callErr != nil {
			return app.failServer(mode, parsed.commandName(), callErr)
		}
		if response.ExitCode != 0 {
			return app.remoteFailure(mode, response.Raw, response.Result, response.ExitCode)
		}
		if mode == outputJSON {
			return writeRemoteJSON(app.stdout, response.Raw, response.ExitCode)
		}
		_, err = fmt.Fprintf(app.stdout, "Database backup job %s: %s; qualification still requires database verify.\n", response.Data.JobID, response.Data.Status)
	case generated.CommandNameDatabaseVerify:
		var input generated.BackupVerifyRequest
		if json.Unmarshal(raw, &input) != nil || generated.ValidateContractJSON(generated.SchemaIDBackupVerifyRequest, raw, generated.ContractExact) != nil {
			return app.fail(mode, parsed.commandName(), generated.ErrorCodeInputInvalid, "database-verify-contract", generated.RunStatusFailed, false)
		}
		response, callErr := control.VerifyDatabase(ctx, config, input)
		if callErr != nil {
			return app.failServer(mode, parsed.commandName(), callErr)
		}
		if response.ExitCode != 0 {
			return app.remoteFailure(mode, response.Raw, response.Result, response.ExitCode)
		}
		if mode == outputJSON {
			return writeRemoteJSON(app.stdout, response.Raw, response.ExitCode)
		}
		_, err = fmt.Fprintf(app.stdout, "Database verification job %s: %s.\n", response.Data.JobID, response.Data.Status)
	case generated.CommandNameDatabaseRestore:
		var input generated.RestoreRequest
		if json.Unmarshal(raw, &input) != nil || generated.ValidateContractJSON(generated.SchemaIDRestoreRequest, raw, generated.ContractExact) != nil {
			return app.fail(mode, parsed.commandName(), generated.ErrorCodeInputInvalid, "database-restore-contract", generated.RunStatusFailed, false)
		}
		response, callErr := control.PlanDatabaseRestore(ctx, config, input)
		if callErr != nil {
			return app.failServer(mode, parsed.commandName(), callErr)
		}
		if response.ExitCode != 0 {
			return app.remoteFailure(mode, response.Raw, response.Result, response.ExitCode)
		}
		if mode == outputJSON {
			return writeRemoteJSON(app.stdout, response.Raw, response.ExitCode)
		}
		_, err = fmt.Fprintf(app.stdout, "Inert database restore plan %s: %s; cutover requires separate human authorization.\n", response.Data.PlanID, response.Data.Status)
	case generated.CommandNameDatabaseExport:
		var input generated.DatabaseExportRequest
		if json.Unmarshal(raw, &input) != nil || generated.ValidateContractJSON(generated.SchemaIDDatabaseExportRequest, raw, generated.ContractExact) != nil {
			return app.fail(mode, parsed.commandName(), generated.ErrorCodeInputInvalid, "database-export-contract", generated.RunStatusFailed, false)
		}
		response, callErr := control.DraftDatabaseExport(ctx, config, input)
		if callErr != nil {
			return app.failServer(mode, parsed.commandName(), callErr)
		}
		if response.ExitCode != 0 {
			return app.remoteFailure(mode, response.Raw, response.Result, response.ExitCode)
		}
		if mode == outputJSON {
			return writeRemoteJSON(app.stdout, response.Raw, response.ExitCode)
		}
		_, err = fmt.Fprintf(app.stdout, "Inert database export draft %s: %s. Safe next action: %s.\n", response.Data.DraftID, response.Data.Status, response.Data.SafeNextAction)
	}
	if err != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	return 0
}
