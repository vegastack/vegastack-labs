package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

func (app *App) runHostLifecycleCommand(ctx context.Context, mode outputMode, p parsedArguments) int {
	control, ok := app.control.(HostControlOperations)
	if !ok {
		return app.fail(mode, p.commandName(), generated.ErrorCodeIntegrityFailure, "host-control", generated.RunStatusFailed, false)
	}
	config := p.Value(generated.FlagConfig)
	if p.commandName() == generated.CommandNameNodeObservationInspect {
		r, e := control.GetHostObservation(ctx, config, p.Value(generated.FlagObservationID))
		if e != nil {
			return app.failServer(mode, p.commandName(), e)
		}
		if r.ExitCode != 0 {
			return app.remoteFailure(mode, r.Raw, r.Result, r.ExitCode)
		}
		if mode == outputJSON {
			return writeRemoteJSON(app.stdout, r.Raw, r.ExitCode)
		}
		_, e = fmt.Fprintf(app.stdout, "Observation %s: %s\nTarget: %s (revision %d)\nState revision: %d; recovery epoch: %d\nDiscovery is not workload admission.\n", r.Data.ObservationID, r.Data.Status, r.Data.TargetID, r.Data.TargetRevision, r.Data.StateRevision, r.Data.RecoveryEpoch)
		if e != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
		return 0
	}
	schema, limit := generated.SchemaIDHostDiscoveryTargetDraftRequest, int64(16384)
	switch p.commandName() {
	case generated.CommandNameNodeActionPrepare:
		schema, limit = generated.SchemaIDHostActionRequest, 131072
	case generated.CommandNameNodeAccessPrepare:
		schema, limit = generated.SchemaIDHostAccessDraftRequest, 1048576
	}
	if app.files == nil {
		return app.fail(mode, p.commandName(), generated.ErrorCodeIntegrityFailure, "host-file", generated.RunStatusFailed, false)
	}
	raw, e := app.files.Read(ctx, p.Value(generated.FlagFile), limit)
	if e != nil {
		return app.failServer(mode, p.commandName(), e)
	}
	if int64(len(raw)) > limit || generated.ValidateContractJSON(schema, raw, generated.ContractExact) != nil {
		return app.fail(mode, p.commandName(), generated.ErrorCodeInputInvalid, "host-request", generated.RunStatusFailed, false)
	}
	switch p.commandName() {
	case generated.CommandNameNodeTargetPrepare:
		var in generated.HostDiscoveryTargetDraftRequest
		_ = json.Unmarshal(raw, &in)
		r, e := control.PrepareHostTarget(ctx, config, in)
		if e != nil {
			return app.failServer(mode, p.commandName(), e)
		}
		if r.ExitCode != 0 {
			return app.remoteFailure(mode, r.Raw, r.Result, r.ExitCode)
		}
		if mode == outputJSON {
			return writeRemoteJSON(app.stdout, r.Raw, r.ExitCode)
		}
		return app.printHostDraft(r.Data.DraftID, r.Data.DeclarationID, r.Data.ContentDigest, r.Data.StateRevision, r.Data.RecoveryEpoch)
	case generated.CommandNameNodeActionPrepare:
		var in generated.HostActionRequest
		_ = json.Unmarshal(raw, &in)
		r, e := control.SubmitHostAction(ctx, config, in)
		if e != nil {
			return app.failServer(mode, p.commandName(), e)
		}
		if r.ExitCode != 0 {
			return app.remoteFailure(mode, r.Raw, r.Result, r.ExitCode)
		}
		if mode == outputJSON {
			return writeRemoteJSON(app.stdout, r.Raw, r.ExitCode)
		}
		return app.printHostDraft(r.Data.DraftID, r.Data.DeclarationID, r.Data.ContentDigest, r.Data.StateRevision, r.Data.RecoveryEpoch)
	case generated.CommandNameNodeAccessPrepare:
		var in generated.HostAccessDraftRequest
		_ = json.Unmarshal(raw, &in)
		r, e := control.SubmitHostAccess(ctx, config, in)
		if e != nil {
			return app.failServer(mode, p.commandName(), e)
		}
		if r.ExitCode != 0 {
			return app.remoteFailure(mode, r.Raw, r.Result, r.ExitCode)
		}
		if mode == outputJSON {
			return writeRemoteJSON(app.stdout, r.Raw, r.ExitCode)
		}
		return app.printHostDraft(r.Data.DraftID, r.Data.DeclarationID, r.Data.ContentDigest, r.Data.StateRevision, r.Data.RecoveryEpoch)
	}
	return app.fail(mode, p.commandName(), generated.ErrorCodeInputInvalid, "host-command", generated.RunStatusFailed, false)
}
func (app *App) printHostDraft(id, declaration, digest string, revision, epoch int64) int {
	_, e := fmt.Fprintf(app.stdout, "Inert host draft %s\nDeclaration: %s\nContent digest: %s\nState revision: %d; recovery epoch: %d\nNext: vsk-labs plan --config <same-profile> --declaration-id %s --revision 1\nReview the exact server plan, request human acknowledgement, then apply separately. This command only prepares the draft.\n", id, declaration, digest, revision, epoch, declaration)
	if e != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	return 0
}
