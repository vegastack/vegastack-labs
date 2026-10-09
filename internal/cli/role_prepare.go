package cli

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/linuxrole"
	"github.com/vegastack/vegastack-labs/internal/localapi"
)

type RoleControlOperations interface {
	SubmitHostAction(context.Context, string, generated.HostActionRequest) (localapi.TypedResponse[generated.HostActionSubmission], error)
}

func (app *App) runRolePrepare(ctx context.Context, mode outputMode, p parsedArguments) int {
	if app.files == nil {
		return app.fail(mode, p.commandName(), generated.ErrorCodeIntegrityFailure, "role-file", generated.RunStatusFailed, false)
	}
	limit := int64(131072)
	if p.commandName() == generated.CommandNameServerPrepare {
		limit = linuxrole.MaximumInput
	}
	raw, err := app.files.Read(ctx, p.Value(generated.FlagFile), limit)
	if err != nil {
		return app.failServer(mode, p.commandName(), err)
	}
	if int64(len(raw)) > limit {
		return app.fail(mode, p.commandName(), generated.ErrorCodeInputInvalid, "role-input", generated.RunStatusFailed, false)
	}
	if p.commandName() == generated.CommandNameServerPrepare {
		input, err := linuxrole.DecodeDesiredInput(raw)
		if err != nil {
			return app.fail(mode, p.commandName(), generated.ErrorCodeInputInvalid, "role-input", generated.RunStatusFailed, false)
		}
		input.RoleBindingDigest = linuxrole.RoleBindingDigest(input)
		input.RenderedPolicyDigest = linuxrole.PolicyDigest(input)
		data, err := linuxrole.Prepare(input)
		if err != nil {
			return app.fail(mode, p.commandName(), generated.ErrorCodeInputInvalid, "role-input", generated.RunStatusFailed, false)
		}
		if mode == outputJSON {
			return app.succeedData(p.commandName(), data)
		}
		if _, err = fmt.Fprintf(app.stdout, "Preparation only: %s role on %s\nPolicy digest: %s\n", data.Input.RoleID, data.Input.HostID, data.PolicyDigest); err != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
		for _, file := range data.Files {
			if _, err = fmt.Fprintf(app.stdout, "Prepared /%s (%s)\n", file.Path, file.Digest); err != nil {
				return exitCodeFor(generated.ErrorCodeIntegrityFailure)
			}
		}
		for _, step := range data.Steps {
			if _, err = fmt.Fprintln(app.stdout, step); err != nil {
				return exitCodeFor(generated.ErrorCodeIntegrityFailure)
			}
		}
		return 0
	}
	var input generated.HostActionRequest
	if generated.ValidateContractJSON(generated.SchemaIDHostActionRequest, raw, generated.ContractExact) != nil || json.Unmarshal(raw, &input) != nil || !linuxrole.IsAction(input.ActionID) {
		return app.fail(mode, p.commandName(), generated.ErrorCodeInputInvalid, "role-request", generated.RunStatusFailed, false)
	}
	if _, err = linuxrole.DecodeDesiredInput([]byte(input.ActionInput)); err != nil {
		return app.fail(mode, p.commandName(), generated.ErrorCodeInputInvalid, "role-input", generated.RunStatusFailed, false)
	}
	control, ok := app.control.(RoleControlOperations)
	if !ok {
		return app.fail(mode, p.commandName(), generated.ErrorCodeIntegrityFailure, "role-control", generated.RunStatusFailed, false)
	}
	r, err := control.SubmitHostAction(ctx, p.Value(generated.FlagConfig), input)
	if err != nil {
		return app.failServer(mode, p.commandName(), err)
	}
	if r.ExitCode != 0 {
		return app.remoteFailure(mode, r.Raw, r.Result, r.ExitCode)
	}
	if mode == outputJSON {
		return writeRemoteJSON(app.stdout, r.Raw, r.ExitCode)
	}
	_, err = fmt.Fprintf(app.stdout, "Inert role draft %s\nDeclaration: %s\nState revision: %d; recovery epoch: %d\nNext: inspect the exact plan, obtain human acknowledgement, then apply. Role installation and workload admission remain pending.\n", r.Data.DraftID, r.Data.DeclarationID, r.Data.StateRevision, r.Data.RecoveryEpoch)
	if err != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	return 0
}
