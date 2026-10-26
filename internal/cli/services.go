package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"github.com/vegastack/vegastack-labs/internal/principal"
)

type ServiceControlOperations interface {
	ListServices(context.Context, string, string, int) (localapi.TypedResponse[generated.ServiceList], error)
	GetService(context.Context, string, string) (localapi.TypedResponse[generated.ServiceRecord], error)
	ObserveService(context.Context, string, string) (localapi.TypedResponse[generated.ServiceObservation], error)
	DraftServiceImport(context.Context, string, generated.ServiceImportDraftRequest) (localapi.TypedResponse[generated.DeclarationRevision], error)
}

func (app *App) runService(ctx context.Context, mode outputMode, p parsedArguments) int {
	control, ok := app.control.(ServiceControlOperations)
	if !ok {
		return app.fail(mode, p.commandName(), generated.ErrorCodePrerequisiteBlocked, "service-control", generated.RunStatusBlocked, false)
	}
	config := p.Value(generated.FlagConfig)
	switch p.commandName() {
	case generated.CommandNameServiceList:
		after, limit := p.Value(generated.FlagAfter), 50
		if value := p.Value(generated.FlagLimit); value != "" {
			n, err := strconv.Atoi(value)
			if err != nil || n < 1 || n > 100 || strconv.Itoa(n) != value {
				return app.fail(mode, p.commandName(), generated.ErrorCodeInputInvalid, "service-query", generated.RunStatusFailed, false)
			}
			limit = n
		}
		if after != "" && !principal.ValidID(after) {
			return app.fail(mode, p.commandName(), generated.ErrorCodeInputInvalid, "service-query", generated.RunStatusFailed, false)
		}
		response, err := control.ListServices(ctx, config, after, limit)
		if err != nil {
			return app.failServer(mode, p.commandName(), err)
		}
		if response.ExitCode != 0 {
			return app.remoteFailure(mode, response.Raw, response.Result, response.ExitCode)
		}
		if mode == outputJSON {
			return writeRemoteJSON(app.stdout, response.Raw, response.ExitCode)
		}
		if len(response.Data.Services) == 0 {
			_, err = fmt.Fprintln(app.stdout, "No registered services in current scope.")
		} else {
			for _, record := range response.Data.Services {
				if _, err = fmt.Fprintf(app.stdout, "%s\t%s\t%s\tHost admission: %s\n", record.Definition.ServiceID, record.Definition.EnvironmentID, record.RegistrationStatus, record.HostAdmission); err != nil {
					break
				}
			}
		}
		if err == nil && response.Data.NextAfter != "" {
			_, err = fmt.Fprintf(app.stdout, "Continue after: %s\n", response.Data.NextAfter)
		}
		if err != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
		return 0
	case generated.CommandNameServiceShow, generated.CommandNameServiceObserve:
		id := p.Value(generated.FlagServiceID)
		if !principal.ValidID(id) {
			return app.fail(mode, p.commandName(), generated.ErrorCodeInputInvalid, "service-id", generated.RunStatusFailed, false)
		}
		if p.commandName() == generated.CommandNameServiceShow {
			response, err := control.GetService(ctx, config, id)
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
			_, err = fmt.Fprintf(app.stdout, "Service: %s\nEnvironment: %s\nOwner: %s\nHost: %s\nRegistration: %s (revision %d)\nHost admission: %s\n", d.Definition.ServiceID, d.Definition.EnvironmentID, d.Definition.OwnerID, d.Definition.HostID, d.RegistrationStatus, d.Revision, d.HostAdmission)
			if err != nil {
				return exitCodeFor(generated.ErrorCodeIntegrityFailure)
			}
			return 0
		}
		response, err := control.ObserveService(ctx, config, id)
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
		_, err = fmt.Fprintf(app.stdout, "Service: %s\nHosting: %s (%s)\nProvider status: %s\nArtifact: %s (%s)\nScan: %s\nSignature: %s\nProvenance: %s\nRunning digest: %s\nHealth: %s\nHost admission: %s\nObserved at: %s\n", d.ServiceID, d.HostingState, d.HostingReason, d.ProviderStatus, d.ArtifactState, d.ArtifactReason, d.ScanState, d.SignatureState, d.ProvenanceState, d.RunningDigestState, d.HealthState, d.HostAdmission, serviceObservationTime(d.ObservedAt))
		if err != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
		return 0
	case generated.CommandNameServiceImportDraft:
		if app.files == nil {
			return app.fail(mode, p.commandName(), generated.ErrorCodeIntegrityFailure, "service-request", generated.RunStatusFailed, false)
		}
		raw, err := app.files.Read(ctx, p.Value(generated.FlagFile), 16384)
		if err != nil {
			return app.failServer(mode, p.commandName(), err)
		}
		var input generated.ServiceImportDraftRequest
		if len(raw) > 16384 || generated.ValidateContractJSON(generated.SchemaIDServiceImportDraftRequest, raw, generated.ContractExact) != nil || json.Unmarshal(raw, &input) != nil {
			return app.fail(mode, p.commandName(), generated.ErrorCodeInputInvalid, "service-request", generated.RunStatusFailed, false)
		}
		response, err := control.DraftServiceImport(ctx, config, input)
		if err != nil {
			return app.failServer(mode, p.commandName(), err)
		}
		if response.ExitCode != 0 {
			return app.remoteFailure(mode, response.Raw, response.Result, response.ExitCode)
		}
		if mode == outputJSON {
			return writeRemoteJSON(app.stdout, response.Raw, response.ExitCode)
		}
		_, err = fmt.Fprintf(app.stdout, "Service %s import drafted\nDeclaration: %s revision %d\nAcknowledge and apply its exact plan to register locally. Host admission: not-verified.\n", input.ServiceID, response.Data.DeclarationID, response.Data.Revision)
		if err != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
		return 0
	}
	return app.fail(mode, p.commandName(), generated.ErrorCodeIntegrityFailure, "service-control", generated.RunStatusFailed, false)
}

func serviceObservationTime(value string) string {
	instant, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return "unknown"
	}
	return instant.In(time.FixedZone("IST", 19800)).Format("02-01-2006 03:04:05 PM IST")
}
