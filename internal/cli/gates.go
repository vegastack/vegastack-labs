package cli

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func (app *App) runGateCommand(ctx context.Context, mode outputMode, parsed parsedArguments) int {
	control, ok := app.control.(GateControlOperations)
	if !ok {
		return app.fail(mode, parsed.commandName(), generated.ErrorCodeIntegrityFailure, "gate-control", generated.RunStatusFailed, false)
	}
	config := parsed.Value(generated.FlagConfig)
	switch parsed.commandName() {
	case generated.CommandNameGateList:
		response, err := control.Gates(ctx, config)
		if err != nil {
			return app.failServer(mode, parsed.commandName(), err)
		}
		if response.ExitCode != 0 {
			return app.remoteFailure(mode, response.Raw, response.Result, response.ExitCode)
		}
		if mode == outputJSON {
			return writeRemoteJSON(app.stdout, response.Raw, response.ExitCode)
		}
		for _, view := range response.Data.Gates {
			if _, err := fmt.Fprintf(app.stdout, "%s: %s (%s; %s)\n", view.Definition.GateID, view.Evaluation.Outcome, view.Evaluation.ReasonCode, view.ApplicabilityReasonCode); err != nil {
				return exitCodeFor(generated.ErrorCodeIntegrityFailure)
			}
		}
		return 0
	case generated.CommandNameGateInspect:
		response, err := control.GetGate(ctx, config, parsed.Value(generated.FlagGateID))
		if err != nil {
			return app.failServer(mode, parsed.commandName(), err)
		}
		if response.ExitCode != 0 {
			return app.remoteFailure(mode, response.Raw, response.Result, response.ExitCode)
		}
		if mode == outputJSON {
			return writeRemoteJSON(app.stdout, response.Raw, response.ExitCode)
		}
		_, err = fmt.Fprintf(app.stdout, "%s: %s\nReason: %s\nApplicability: %s\nEvidence source: %s\n", response.Data.Definition.GateID, response.Data.Evaluation.Outcome, response.Data.Evaluation.ReasonCode, response.Data.ApplicabilityReasonCode, response.Data.Evaluation.EvidenceSource)
		if err != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
		return 0
	case generated.CommandNameGateCheck:
		response, err := control.CheckGate(ctx, config, parsed.Value(generated.FlagGateID), parsed.Value(generated.FlagSubjectID))
		if err != nil {
			return app.failServer(mode, parsed.commandName(), err)
		}
		if response.ExitCode != 0 {
			return app.remoteFailure(mode, response.Raw, response.Result, response.ExitCode)
		}
		if mode == outputJSON {
			return writeRemoteJSON(app.stdout, response.Raw, response.ExitCode)
		}
		_, err = fmt.Fprintf(app.stdout, "%s on %s: %s\nReason: %s\nEvidence source: %s\nReady for input: %t\n", response.Data.GateID, response.Data.SubjectID, response.Data.Outcome, response.Data.ReasonCode, response.Data.EvidenceSource, response.Data.ReadyForInput)
		if err != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
		return 0
	case generated.CommandNameGateEvidence:
		if app.files == nil {
			return app.fail(mode, parsed.commandName(), generated.ErrorCodeIntegrityFailure, "gate-file", generated.RunStatusFailed, false)
		}
		raw, err := app.files.Read(ctx, parsed.Value(generated.FlagFile), 65536)
		if err != nil {
			return app.failServer(mode, parsed.commandName(), err)
		}
		if generated.ValidateContractJSON(generated.SchemaIDGateEvidenceRequest, raw, generated.ContractExact) != nil {
			return app.fail(mode, parsed.commandName(), generated.ErrorCodeInputInvalid, "gate-evidence-contract", generated.RunStatusFailed, false)
		}
		var input generated.GateEvidenceRequest
		if json.Unmarshal(raw, &input) != nil {
			return app.fail(mode, parsed.commandName(), generated.ErrorCodeInputInvalid, "gate-evidence-contract", generated.RunStatusFailed, false)
		}
		response, err := control.SubmitGateEvidence(ctx, config, input)
		if err != nil {
			return app.failServer(mode, parsed.commandName(), err)
		}
		return app.gateSubmission(mode, parsed.commandName(), response.Raw, response.Result, response.ExitCode, response.Data.DraftID, response.Data.ChangeID)
	case generated.CommandNameGateProfileDraft:
		if app.files == nil {
			return app.fail(mode, parsed.commandName(), generated.ErrorCodeIntegrityFailure, "gate-file", generated.RunStatusFailed, false)
		}
		raw, err := app.files.Read(ctx, parsed.Value(generated.FlagFile), 4096)
		if err != nil {
			return app.failServer(mode, parsed.commandName(), err)
		}
		if generated.ValidateContractJSON(generated.SchemaIDGateProfileDraftRequest, raw, generated.ContractExact) != nil {
			return app.fail(mode, parsed.commandName(), generated.ErrorCodeInputInvalid, "profile-draft-contract", generated.RunStatusFailed, false)
		}
		var input generated.GateProfileDraftRequest
		if json.Unmarshal(raw, &input) != nil {
			return app.fail(mode, parsed.commandName(), generated.ErrorCodeInputInvalid, "profile-draft-contract", generated.RunStatusFailed, false)
		}
		response, err := control.SubmitProfileDraft(ctx, config, input)
		if err != nil {
			return app.failServer(mode, parsed.commandName(), err)
		}
		return app.gateSubmission(mode, parsed.commandName(), response.Raw, response.Result, response.ExitCode, response.Data.DraftID, response.Data.ChangeID)
	}
	return app.fail(mode, parsed.commandName(), generated.ErrorCodeIntegrityFailure, "gate-command", generated.RunStatusFailed, false)
}

func (app *App) gateSubmission(mode outputMode, command string, raw []byte, result generated.RunResult, exitCode int, draftID, changeID string) int {
	if exitCode != 0 {
		return app.remoteFailure(mode, raw, result, exitCode)
	}
	if mode == outputJSON {
		return writeRemoteJSON(app.stdout, raw, exitCode)
	}
	if _, err := fmt.Fprintf(app.stdout, "Inert draft %s; change %s. Create an exact plan and obtain human approval before apply.\n", draftID, changeID); err != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	return 0
}
