package cli

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/vegastack/vegastack-labs/internal/generated"
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
