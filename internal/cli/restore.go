package cli

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func (app *App) runRestoreOperation(ctx context.Context, mode outputMode, parsed parsedArguments) int {
	control, ok := app.control.(RestoreControlOperations)
	if !ok || app.files == nil {
		return app.fail(mode, parsed.commandName(), generated.ErrorCodeIntegrityFailure, "restore-control", generated.RunStatusFailed, false)
	}
	raw, err := app.files.Read(ctx, parsed.Value(generated.FlagFile), 262144)
	if err != nil {
		return app.failServer(mode, parsed.commandName(), err)
	}
	config := parsed.Value(generated.FlagConfig)
	switch parsed.commandName() {
	case generated.CommandNameRestorePlan:
		var input generated.RestoreRequest
		if json.Unmarshal(raw, &input) != nil || generated.ValidateContractJSON(generated.SchemaIDRestoreRequest, raw, generated.ContractExact) != nil {
			return app.fail(mode, parsed.commandName(), generated.ErrorCodeInputInvalid, "restore-plan-contract", generated.RunStatusFailed, false)
		}
		response, callErr := control.PlanRestore(ctx, config, input)
		if callErr != nil {
			return app.failServer(mode, parsed.commandName(), callErr)
		}
		if response.ExitCode != 0 {
			return app.remoteFailure(mode, response.Raw, response.Result, response.ExitCode)
		}
		if mode == outputJSON {
			return writeRemoteJSON(app.stdout, response.Raw, response.ExitCode)
		}
		_, err = fmt.Fprintf(app.stdout, "Restore plan %s: %s.\n", response.Data.PlanID, response.Data.Status)
	case generated.CommandNameRestoreRun:
		var input generated.RestoreRunRequest
		if json.Unmarshal(raw, &input) != nil || generated.ValidateContractJSON(generated.SchemaIDRestoreRunRequest, raw, generated.ContractExact) != nil {
			return app.fail(mode, parsed.commandName(), generated.ErrorCodeInputInvalid, "restore-run-contract", generated.RunStatusFailed, false)
		}
		response, callErr := control.RunRestore(ctx, config, input)
		if callErr != nil {
			return app.failServer(mode, parsed.commandName(), callErr)
		}
		if response.ExitCode != 0 {
			return app.remoteFailure(mode, response.Raw, response.Result, response.ExitCode)
		}
		if mode == outputJSON {
			return writeRemoteJSON(app.stdout, response.Raw, response.ExitCode)
		}
		_, err = fmt.Fprintf(app.stdout, "Restore candidate for plan %s: %s.\n", response.Data.PlanID, response.Data.Status)
	case generated.CommandNameRestoreVerify:
		var input generated.RestoreVerifyRequest
		if json.Unmarshal(raw, &input) != nil || generated.ValidateContractJSON(generated.SchemaIDRestoreVerifyRequest, raw, generated.ContractExact) != nil {
			return app.fail(mode, parsed.commandName(), generated.ErrorCodeInputInvalid, "restore-verify-contract", generated.RunStatusFailed, false)
		}
		response, callErr := control.VerifyRestore(ctx, config, input)
		if callErr != nil {
			return app.failServer(mode, parsed.commandName(), callErr)
		}
		if response.ExitCode != 0 {
			return app.remoteFailure(mode, response.Raw, response.Result, response.ExitCode)
		}
		if mode == outputJSON {
			return writeRemoteJSON(app.stdout, response.Raw, response.ExitCode)
		}
		_, err = fmt.Fprintf(app.stdout, "Recovered authority for plan %s: %s.\n", response.Data.PlanID, response.Data.Status)
	}
	if err != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	return 0
}
