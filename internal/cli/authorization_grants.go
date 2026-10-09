package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

func (app *App) runGrantBatchDraft(ctx context.Context, mode outputMode, p parsedArguments) int {
	control, ok := app.control.(AuthorizationGrantControlOperations)
	if !ok || app.files == nil {
		return app.fail(mode, p.commandName(), generated.ErrorCodeIntegrityFailure, "grant-control", generated.RunStatusFailed, false)
	}
	raw, err := app.files.Read(ctx, p.Value(generated.FlagFile), 32768)
	if err != nil {
		return app.failServer(mode, p.commandName(), err)
	}
	if len(raw) > 32768 || generated.ValidateContractJSON(generated.SchemaIDAuthorizationGrantBatchRequest, raw, generated.ContractExact) != nil {
		return app.fail(mode, p.commandName(), generated.ErrorCodeInputInvalid, "grant-request", generated.RunStatusFailed, false)
	}
	var input generated.AuthorizationGrantBatchRequest
	_ = json.Unmarshal(raw, &input)
	r, err := control.DraftAuthorizationGrants(ctx, p.Value(generated.FlagConfig), input)
	if err != nil {
		return app.failServer(mode, p.commandName(), err)
	}
	if r.ExitCode != 0 {
		return app.remoteFailure(mode, r.Raw, r.Result, r.ExitCode)
	}
	if mode == outputJSON {
		return writeRemoteJSON(app.stdout, r.Raw, r.ExitCode)
	}
	if _, err = fmt.Fprintf(app.stdout, "Grant batch for %s: %d changes drafted\nDeclaration: %s (revision %d)\nPermissions remain unchanged until this exact plan is acknowledged and applied.\n", input.PrincipalID, len(input.Changes), r.Data.DeclarationID, r.Data.Revision); err != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	return 0
}
