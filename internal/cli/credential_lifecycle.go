package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func (app *App) runCredentialLifecycle(ctx context.Context, parsed parsedArguments) int {
	control, ok := app.credentials.(CredentialLifecycleControlOperations)
	if !ok || app.files == nil {
		return app.fail(parsed.output, parsed.commandName(), generated.ErrorCodeIntegrityFailure, "control-operations", generated.RunStatusFailed, false)
	}
	raw, err := app.files.Read(ctx, parsed.Value(generated.FlagFile), 262144)
	if err != nil {
		return app.failServer(parsed.output, parsed.commandName(), err)
	}
	var input generated.CredentialLifecycleRequest
	if generated.ValidateContractJSON(generated.SchemaIDCredentialLifecycleRequest, raw, generated.ContractExact) != nil || json.Unmarshal(raw, &input) != nil || input.Action != "credential."+strings.TrimPrefix(parsed.commandName(), "credential ") {
		return app.fail(parsed.output, parsed.commandName(), generated.ErrorCodeInputInvalid, "credential-lifecycle-contract", generated.RunStatusFailed, false)
	}
	response, err := control.CreateCredentialLifecycleDraft(ctx, parsed.Value(generated.FlagConfig), input)
	if err != nil {
		return app.failServer(parsed.output, parsed.commandName(), err)
	}
	if response.ExitCode != 0 {
		return app.remoteFailure(parsed.output, response.Raw, response.Result, response.ExitCode)
	}
	if parsed.output == outputJSON {
		return writeRemoteJSON(app.stdout, response.Raw, response.ExitCode)
	}
	if _, err := fmt.Fprintf(app.stdout, "Credential lifecycle draft %s\nAction: %s\nReference: %s\nChange: %s\nState revision: %d\nRecovery epoch: %d\n", response.Data.Status, response.Data.Action, response.Data.ReferenceID, response.Data.ChangeID, response.Data.StateRevision, response.Data.RecoveryEpoch); err != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	return response.ExitCode
}
