package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"strings"
)

func (app *App) runHostLifecycleCommand(ctx context.Context, mode outputMode, p parsedArguments) int {
	control, ok := app.control.(HostControlOperations)
	if !ok {
		return app.fail(mode, p.commandName(), generated.ErrorCodeIntegrityFailure, "host-control", generated.RunStatusFailed, false)
	}
	config := p.Value(generated.FlagConfig)
	if p.commandName() == generated.CommandNameNodeReplacementInspect {
		r, e := control.GetHostReplacement(ctx, config, p.Value(generated.FlagReplacementID))
		if e != nil {
			return app.failServer(mode, p.commandName(), e)
		}
		if r.ExitCode != 0 {
			return app.remoteFailure(mode, r.Raw, r.Result, r.ExitCode)
		}
		if mode == outputJSON {
			return writeRemoteJSON(app.stdout, r.Raw, r.ExitCode)
		}
		_, e = fmt.Fprintf(app.stdout, "Replacement %s: %s\nFormer host: %s; replacement host: %s\nRestoration: %s\nOwnership generation: %d → %d\nBlockers: %s\nNext action: %s\nState revision: %d; recovery epoch: %d\n", r.Data.ReplacementID, r.Data.Status, r.Data.OldHostID, r.Data.NewHostID, r.Data.RestorationClass, r.Data.PriorOwnershipGeneration, r.Data.ProposedOwnershipGeneration, strings.Join(r.Data.Blockers, ", "), r.Data.NextAction, r.Data.StateRevision, r.Data.RecoveryEpoch)
		if e != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
		return 0
	}
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
	case generated.CommandNameNodeReplacementPrepare:
		schema, limit = generated.SchemaIDHostReplacementRequest, 32768
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
	case generated.CommandNameNodeReplacementPrepare:
		var in generated.HostReplacementRequest
		_ = json.Unmarshal(raw, &in)
		r, e := control.PrepareHostReplacement(ctx, config, in)
		if e != nil {
			return app.failServer(mode, p.commandName(), e)
		}
		if r.ExitCode != 0 {
			return app.remoteFailure(mode, r.Raw, r.Result, r.ExitCode)
		}
		if mode == outputJSON {
			return writeRemoteJSON(app.stdout, r.Raw, r.ExitCode)
		}
		if _, e = fmt.Fprintf(app.stdout, "Replacement %s: %s draft\nFormer host: %s; replacement host: %s\nAliases: %d; restoration: %s\n", r.Data.ReplacementID, in.Operation, in.OldHostID, in.NewHostID, len(in.AliasBindings), in.RestorationClass); e != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
		return app.printHostDraft(r.Data.DraftID, r.Data.DeclarationID, r.Data.ContentDigest, r.Data.StateRevision, r.Data.RecoveryEpoch)
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
