package cli

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
)

// runBackupCommand handles `backup policy draft`: it reads one exact typed
// backup-policy-draft-request JSON file and submits it as an inert draft. It
// activates nothing; an exact plan and human approval remain required to apply.
func (app *App) runBackupCommand(ctx context.Context, mode outputMode, parsed parsedArguments) int {
	control, ok := app.control.(BackupControlOperations)
	if !ok {
		return app.fail(mode, parsed.commandName(), generated.ErrorCodeIntegrityFailure, "backup-control", generated.RunStatusFailed, false)
	}
	if app.files == nil {
		return app.fail(mode, parsed.commandName(), generated.ErrorCodeIntegrityFailure, "backup-file", generated.RunStatusFailed, false)
	}
	config := parsed.Value(generated.FlagConfig)
	raw, err := app.files.Read(ctx, parsed.Value(generated.FlagFile), 65536)
	if err != nil {
		return app.failServer(mode, parsed.commandName(), err)
	}
	if generated.ValidateContractJSON(generated.SchemaIDBackupPolicyDraftRequest, raw, generated.ContractExact) != nil {
		return app.fail(mode, parsed.commandName(), generated.ErrorCodeInputInvalid, "backup-policy-draft-contract", generated.RunStatusFailed, false)
	}
	var input generated.BackupPolicyDraftRequest
	if json.Unmarshal(raw, &input) != nil {
		return app.fail(mode, parsed.commandName(), generated.ErrorCodeInputInvalid, "backup-policy-draft-contract", generated.RunStatusFailed, false)
	}
	response, err := control.SubmitBackupPolicyDraft(ctx, config, input)
	if err != nil {
		return app.failServer(mode, parsed.commandName(), err)
	}
	if response.ExitCode != 0 {
		return app.remoteFailure(mode, response.Raw, response.Result, response.ExitCode)
	}
	if mode == outputJSON {
		return writeRemoteJSON(app.stdout, response.Raw, response.ExitCode)
	}
	if _, err := fmt.Fprintf(app.stdout, "Inert backup policy draft %s (digest %s). Bind it through the declaration/plan/run flow and obtain human approval before any backup runs.\n", response.Data.DraftID, response.Data.PolicyDigest); err != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	return 0
}

func (app *App) runBackupOperation(ctx context.Context, mode outputMode, parsed parsedArguments) int {
	control, ok := app.control.(BackupRunControlOperations)
	if !ok {
		return app.fail(mode, parsed.commandName(), generated.ErrorCodeIntegrityFailure, "backup-control", generated.RunStatusFailed, false)
	}
	config := parsed.Value(generated.FlagConfig)
	if parsed.commandName() == generated.CommandNameBackupStatus {
		response, err := control.BackupStatus(ctx, config)
		if err != nil {
			return app.failServer(mode, parsed.commandName(), err)
		}
		if response.ExitCode != 0 {
			return app.remoteFailure(mode, response.Raw, response.Result, response.ExitCode)
		}
		if mode == outputJSON {
			return writeRemoteJSON(app.stdout, response.Raw, response.ExitCode)
		}
		_, err = fmt.Fprintf(app.stdout, "%d backup jobs, %d local verification attempts, %d last-good points.\n", len(response.Data.Jobs), len(response.Data.Verifications), len(response.Data.LastGood))
		if err != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
		return 0
	}
	if app.files == nil {
		return app.fail(mode, parsed.commandName(), generated.ErrorCodeIntegrityFailure, "backup-file", generated.RunStatusFailed, false)
	}
	raw, err := app.files.Read(ctx, parsed.Value(generated.FlagFile), 4096)
	if err != nil {
		return app.failServer(mode, parsed.commandName(), err)
	}
	var response localapi.TypedResponse[generated.BackupJob]
	switch parsed.commandName() {
	case generated.CommandNameBackupRun:
		if generated.ValidateContractJSON(generated.SchemaIDBackupRunRequest, raw, generated.ContractExact) != nil {
			return app.fail(mode, parsed.commandName(), generated.ErrorCodeInputInvalid, "backup-run-contract", generated.RunStatusFailed, false)
		}
		var input generated.BackupRunRequest
		if json.Unmarshal(raw, &input) != nil {
			return app.fail(mode, parsed.commandName(), generated.ErrorCodeInputInvalid, "backup-run-contract", generated.RunStatusFailed, false)
		}
		response, err = control.RunBackup(ctx, config, input)
	case generated.CommandNameBackupVerify:
		if generated.ValidateContractJSON(generated.SchemaIDBackupVerifyRequest, raw, generated.ContractExact) != nil {
			return app.fail(mode, parsed.commandName(), generated.ErrorCodeInputInvalid, "backup-verify-contract", generated.RunStatusFailed, false)
		}
		var input generated.BackupVerifyRequest
		if json.Unmarshal(raw, &input) != nil {
			return app.fail(mode, parsed.commandName(), generated.ErrorCodeInputInvalid, "backup-verify-contract", generated.RunStatusFailed, false)
		}
		response, err = control.VerifyBackup(ctx, config, input)
	}
	if err != nil {
		return app.failServer(mode, parsed.commandName(), err)
	}
	if response.ExitCode != 0 {
		return app.remoteFailure(mode, response.Raw, response.Result, response.ExitCode)
	}
	if mode == outputJSON {
		return writeRemoteJSON(app.stdout, response.Raw, response.ExitCode)
	}
	_, err = fmt.Fprintf(app.stdout, "Backup job %s: %s.\n", response.Data.JobID, response.Data.Status)
	if err != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	return 0
}
