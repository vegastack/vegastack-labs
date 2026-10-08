package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"strings"
)

func (app *App) runHostCommand(ctx context.Context, mode outputMode, p parsedArguments) int {
	control, ok := app.control.(HostControlOperations)
	if !ok {
		return app.fail(mode, p.commandName(), generated.ErrorCodeIntegrityFailure, "host-control", generated.RunStatusFailed, false)
	}
	config := p.Value(generated.FlagConfig)
	if p.commandName() == generated.CommandNameNodeInspect {
		r, err := control.GetManagedHost(ctx, config, p.Value(generated.FlagHostID))
		if err != nil {
			return app.failServer(mode, p.commandName(), err)
		}
		if r.ExitCode != 0 {
			return app.remoteFailure(mode, r.Raw, r.Result, r.ExitCode)
		}
		if mode == outputJSON {
			return writeRemoteJSON(app.stdout, r.Raw, r.ExitCode)
		}
		_, err = fmt.Fprintf(app.stdout, "Host %s: %s\nTarget: %s\nObservation: %s\nProfile: %s\nIdentity class: %s\nState revision: %d; recovery epoch: %d\n", r.Data.HostID, r.Data.Status, r.Data.TargetID, r.Data.ObservationID, r.Data.ProfileID, r.Data.IdentityClass, r.Data.StateRevision, r.Data.RecoveryEpoch)
		if err != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
		return 0
	}
	if app.files == nil {
		return app.fail(mode, p.commandName(), generated.ErrorCodeIntegrityFailure, "host-file", generated.RunStatusFailed, false)
	}
	raw, err := app.files.Read(ctx, p.Value(generated.FlagFile), 16384)
	if err != nil {
		return app.failServer(mode, p.commandName(), err)
	}
	schema := generated.SchemaIDHostDiscoveryRequest
	if p.commandName() == generated.CommandNameNodeAdd {
		schema = generated.SchemaIDHostAdoptionRequest
	}
	if len(raw) > 16384 || generated.ValidateContractJSON(schema, raw, generated.ContractExact) != nil {
		return app.fail(mode, p.commandName(), generated.ErrorCodeInputInvalid, "host-request", generated.RunStatusFailed, false)
	}
	if p.commandName() == generated.CommandNameNodeDiscover {
		var input generated.HostDiscoveryRequest
		if json.Unmarshal(raw, &input) != nil {
			return app.fail(mode, p.commandName(), generated.ErrorCodeInputInvalid, "host-request", generated.RunStatusFailed, false)
		}
		r, err := control.DiscoverHost(ctx, config, input)
		if err != nil {
			return app.failServer(mode, p.commandName(), err)
		}
		if r.ExitCode != 0 {
			return app.remoteFailure(mode, r.Raw, r.Result, r.ExitCode)
		}
		if mode == outputJSON {
			return writeRemoteJSON(app.stdout, r.Raw, r.ExitCode)
		}
		o := r.Data.Observation
		_, err = fmt.Fprintf(app.stdout, "Observation %s: %s\nTarget: %s (revision %d)\nState revision: %d; recovery epoch: %d\nBlockers: %s\nDiscovery does not admit workloads.\n", o.ObservationID, o.Status, o.TargetID, o.TargetRevision, o.StateRevision, o.RecoveryEpoch, strings.Join(o.Blockers, ", "))
		if err != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
		return 0
	}
	var input generated.HostAdoptionRequest
	if json.Unmarshal(raw, &input) != nil {
		return app.fail(mode, p.commandName(), generated.ErrorCodeInputInvalid, "host-request", generated.RunStatusFailed, false)
	}
	r, err := control.SubmitHostAdoption(ctx, config, input)
	if err != nil {
		return app.failServer(mode, p.commandName(), err)
	}
	if r.ExitCode != 0 {
		return app.remoteFailure(mode, r.Raw, r.Result, r.ExitCode)
	}
	if mode == outputJSON {
		return writeRemoteJSON(app.stdout, r.Raw, r.ExitCode)
	}
	_, err = fmt.Fprintf(app.stdout, "Inert registration draft %s\nDeclaration: %s\nState revision: %d; recovery epoch: %d\nNext: create an exact plan for declaration revision 1, obtain human acknowledgement, then apply. This command only prepares the draft.\n", r.Data.DraftID, r.Data.DeclarationID, r.Data.StateRevision, r.Data.RecoveryEpoch)
	if err != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	return 0
}
