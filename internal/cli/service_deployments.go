package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"github.com/vegastack/vegastack-labs/internal/principal"
)

type ServiceDeploymentControlOperations interface {
	DraftServiceDeployment(context.Context, string, generated.ServiceDeploymentDraftRequest) (localapi.TypedResponse[generated.DeclarationRevision], error)
	GetServiceDeployment(context.Context, string, string) (localapi.TypedResponse[generated.ServiceDeploymentRecord], error)
}

func (app *App) runServiceDeployment(ctx context.Context, mode outputMode, p parsedArguments) int {
	control, ok := app.control.(ServiceDeploymentControlOperations)
	if !ok {
		return app.fail(mode, p.commandName(), generated.ErrorCodePrerequisiteBlocked, "service-deployment-control", generated.RunStatusBlocked, false)
	}
	config := p.Value(generated.FlagConfig)
	if p.commandName() == generated.CommandNameServiceDeploymentDraft {
		if app.files == nil {
			return app.fail(mode, p.commandName(), generated.ErrorCodeIntegrityFailure, "service-deployment-request", generated.RunStatusFailed, false)
		}
		raw, err := app.files.Read(ctx, p.Value(generated.FlagFile), 16384)
		if err != nil {
			return app.failServer(mode, p.commandName(), err)
		}
		var in generated.ServiceDeploymentDraftRequest
		if len(raw) > 16384 || generated.ValidateContractJSON(generated.SchemaIDServiceDeploymentDraftRequest, raw, generated.ContractExact) != nil || json.Unmarshal(raw, &in) != nil {
			return app.fail(mode, p.commandName(), generated.ErrorCodeInputInvalid, "service-deployment-request", generated.RunStatusFailed, false)
		}
		response, err := control.DraftServiceDeployment(ctx, config, in)
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
	response, err := control.GetServiceDeployment(ctx, config, id)
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
	_, err = fmt.Fprintf(app.stdout, "Service: %s\nDeployment: %s (revision %d)\nAction: %s\nArtifact: %s\nProvider stage: %s\nProvider receipt: %s\nRunning: %t\nHealthy: %t\nCompleted at: %s\n", d.Request.Definition.ServiceID, d.Status, d.Revision, d.Request.Action, d.Request.Artifact.ArtifactID, d.ProviderStage, d.ProviderReceiptID, d.Running, d.Healthy, serviceObservationTime(d.CompletedAt))
	if err != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	return 0
}
