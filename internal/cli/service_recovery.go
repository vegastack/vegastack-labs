package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"github.com/vegastack/vegastack-labs/internal/principal"
)

type ServiceRecoveryControlOperations interface {
	DraftServiceRecovery(context.Context, string, generated.ServiceRecoveryDraftRequest) (localapi.TypedResponse[generated.DeclarationRevision], error)
	GetServiceRecovery(context.Context, string, string) (localapi.TypedResponse[generated.ServiceRecoveryRecord], error)
}

func (app *App) runServiceRecovery(ctx context.Context, mode outputMode, p parsedArguments) int {
	control, ok := app.control.(ServiceRecoveryControlOperations)
	if !ok {
		return app.fail(mode, p.commandName(), generated.ErrorCodePrerequisiteBlocked, "service-recovery-control", generated.RunStatusBlocked, false)
	}
	config := p.Value(generated.FlagConfig)
	if p.commandName() == generated.CommandNameServiceRecoveryDraft {
		if app.files == nil {
			return app.fail(mode, p.commandName(), generated.ErrorCodeIntegrityFailure, "service-recovery-request", generated.RunStatusFailed, false)
		}
		raw, err := app.files.Read(ctx, p.Value(generated.FlagFile), 16384)
		if err != nil {
			return app.failServer(mode, p.commandName(), err)
		}
		var in generated.ServiceRecoveryDraftRequest
		if len(raw) > 16384 || generated.ValidateContractJSON(generated.SchemaIDServiceRecoveryDraftRequest, raw, generated.ContractExact) != nil || json.Unmarshal(raw, &in) != nil {
			return app.fail(mode, p.commandName(), generated.ErrorCodeInputInvalid, "service-recovery-request", generated.RunStatusFailed, false)
		}
		response, err := control.DraftServiceRecovery(ctx, config, in)
		if err != nil {
			return app.failServer(mode, p.commandName(), err)
		}
		if response.ExitCode != 0 {
			return app.remoteFailure(mode, response.Raw, response.Result, response.ExitCode)
		}
		if mode == outputJSON {
			return writeRemoteJSON(app.stdout, response.Raw, response.ExitCode)
		}
		_, err = fmt.Fprintf(app.stdout, "Service %s %s drafted\nDeclaration: %s revision %d\nAcknowledge and apply its exact plan to execute.\n", in.ServiceID, in.Action, response.Data.DeclarationID, response.Data.Revision)
		if err != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
		return 0
	}
	id := p.Value(generated.FlagServiceID)
	if !principal.ValidID(id) {
		return app.fail(mode, p.commandName(), generated.ErrorCodeInputInvalid, "service-id", generated.RunStatusFailed, false)
	}
	response, err := control.GetServiceRecovery(ctx, config, id)
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
	_, err = fmt.Fprintf(app.stdout, "Service: %s\nRecovery: %s (revision %d)\nAction: %s\nBackup point: %s\nSource resumed: %t\nSource fenced: %t\nIsolated restore verified: %t\nNext action: %s\nCompleted at: %s\n", d.Request.Definition.ServiceID, d.Status, d.Revision, d.Request.Action, d.BackupPointID, d.SourceResumed, d.SourceFenced, d.IsolatedRestoreVerified, d.NextAction, serviceObservationTime(d.CompletedAt))
	if err != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	return 0
}
