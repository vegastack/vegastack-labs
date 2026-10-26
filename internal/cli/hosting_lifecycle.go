package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"github.com/vegastack/vegastack-labs/internal/principal"
)

type HostingLifecycleControlOperations interface {
	DraftHostingLifecycle(context.Context, string, generated.HostingLifecycleDraftRequest) (localapi.TypedResponse[generated.DeclarationRevision], error)
	GetHostingLifecycle(context.Context, string, string) (localapi.TypedResponse[generated.HostingLifecycleRecord], error)
}

func (app *App) runHostingLifecycle(ctx context.Context, mode outputMode, p parsedArguments) int {
	control, ok := app.control.(HostingLifecycleControlOperations)
	if !ok {
		return app.fail(mode, p.commandName(), generated.ErrorCodePrerequisiteBlocked, "hosting-lifecycle-control", generated.RunStatusBlocked, false)
	}
	config := p.Value(generated.FlagConfig)
	if p.commandName() == generated.CommandNameHostingLifecycleDraft {
		if app.files == nil {
			return app.fail(mode, p.commandName(), generated.ErrorCodeIntegrityFailure, "hosting-lifecycle-request", generated.RunStatusFailed, false)
		}
		raw, err := app.files.Read(ctx, p.Value(generated.FlagFile), 16384)
		if err != nil {
			return app.failServer(mode, p.commandName(), err)
		}
		var in generated.HostingLifecycleDraftRequest
		if len(raw) > 16384 || generated.ValidateContractJSON(generated.SchemaIDHostingLifecycleDraftRequest, raw, generated.ContractExact) != nil || json.Unmarshal(raw, &in) != nil {
			return app.fail(mode, p.commandName(), generated.ErrorCodeInputInvalid, "hosting-lifecycle-request", generated.RunStatusFailed, false)
		}
		response, err := control.DraftHostingLifecycle(ctx, config, in)
		if err != nil {
			return app.failServer(mode, p.commandName(), err)
		}
		if response.ExitCode != 0 {
			return app.remoteFailure(mode, response.Raw, response.Result, response.ExitCode)
		}
		if mode == outputJSON {
			return writeRemoteJSON(app.stdout, response.Raw, response.ExitCode)
		}
		_, err = fmt.Fprintf(app.stdout, "Service %s %s drafted\nDeclaration: %s revision %d\nAcknowledge and apply its exact plan to execute.\n", in.TargetID, in.Action, response.Data.DeclarationID, response.Data.Revision)
		if err != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
		return 0
	}
	id := p.Value(generated.FlagTargetID)
	if !principal.ValidID(id) {
		return app.fail(mode, p.commandName(), generated.ErrorCodeInputInvalid, "service-id", generated.RunStatusFailed, false)
	}
	response, err := control.GetHostingLifecycle(ctx, config, id)
	if err != nil {
		return app.failServer(mode, p.commandName(), err)
	}
	if response.ExitCode != 0 {
		return app.remoteFailure(mode, response.Raw, response.Result, response.ExitCode)
	}
	if mode == outputJSON {
		return writeRemoteJSON(app.stdout, response.Raw, response.ExitCode)
	}
	d := response.Data
	_, err = fmt.Fprintf(app.stdout, "Hosting target: %s\nLifecycle: %s (revision %d)\nAction: %s\nCompleted at: %s\n", d.Request.TargetID, d.Status, d.Revision, d.Request.Action, serviceObservationTime(d.CompletedAt))
	if err != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	return 0
}
