package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
)

type QualificationControlOperations interface {
	RunSlackFixturePeer(context.Context) error
	InspectQualification(context.Context, string, generated.QualificationInspectRequest) (localapi.TypedResponse[generated.QualificationInspectData], error)
	RunNativeQualification(context.Context, generated.QualificationScope) (generated.NativeReport, error)
	ExecuteQualificationStep(context.Context, string, generated.NativeStepRequest) (generated.NativeStepResult, error)
}

func (app *App) runQualification(ctx context.Context, mode outputMode, p parsedArguments) int {
	control, ok := app.control.(QualificationControlOperations)
	if !ok || app.files == nil {
		return app.fail(mode, p.commandName(), generated.ErrorCodeIntegrityFailure, "qualification-control", generated.RunStatusFailed, false)
	}
	if p.commandName() == generated.CommandNameQualificationFixturePeer {
		if err := control.RunSlackFixturePeer(ctx); err != nil {
			return app.failServer(mode, p.commandName(), err)
		}
		if mode == outputJSON {
			return app.succeedData(p.commandName(), struct{}{})
		}
		_, err := fmt.Fprintln(app.stdout, "Finite qualification approval peer stopped.")
		if err != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
		return 0
	}
	raw, err := app.files.Read(ctx, p.Value(generated.FlagFile), 32768)
	if err != nil {
		return app.failServer(mode, p.commandName(), err)
	}
	schema := generated.SchemaIDQualificationInspectRequest
	if p.commandName() == generated.CommandNameQualificationNative {
		schema = generated.SchemaIDQualificationScope
	}
	if p.commandName() == generated.CommandNameQualificationStep {
		schema = generated.SchemaIDNativeStepRequest
	}
	if len(raw) > 32768 || generated.ValidateContractJSON(schema, raw, generated.ContractExact) != nil {
		return app.fail(mode, p.commandName(), generated.ErrorCodeInputInvalid, "qualification-input", generated.RunStatusFailed, false)
	}
	var data any
	switch p.commandName() {
	case generated.CommandNameQualificationInspect:
		var in generated.QualificationInspectRequest
		_ = json.Unmarshal(raw, &in)
		response, e := control.InspectQualification(ctx, p.Value(generated.FlagConfig), in)
		if e != nil {
			return app.failServer(mode, p.commandName(), e)
		}
		if response.ExitCode != 0 {
			return app.remoteFailure(mode, response.Raw, response.Result, response.ExitCode)
		}
		if mode == outputJSON {
			return writeRemoteJSON(app.stdout, response.Raw, response.ExitCode)
		}
		_, e = fmt.Fprintf(app.stdout, "Suitability observations for %s; qualification and provisioning remain separate.\n", response.Data.Facts.TargetID)
		if e != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
		return 0
	case generated.CommandNameQualificationNative:
		if p.Value(generated.FlagConfig) != "/etc/vsk-labs/native/client.json" {
			return app.fail(mode, p.commandName(), generated.ErrorCodeInputInvalid, "qualification-client-profile", generated.RunStatusFailed, false)
		}
		var in generated.QualificationScope
		_ = json.Unmarshal(raw, &in)
		data, err = control.RunNativeQualification(ctx, in)
	case generated.CommandNameQualificationStep:
		var in generated.NativeStepRequest
		_ = json.Unmarshal(raw, &in)
		if p.Value(generated.FlagFile) != fmt.Sprintf("/run/vsk-labs-native/%s-%d.json", in.ScenarioID, in.Ordinal) {
			return app.fail(mode, p.commandName(), generated.ErrorCodeInputInvalid, "qualification-step-slot", generated.RunStatusFailed, false)
		}
		data, err = control.ExecuteQualificationStep(ctx, p.Value(generated.FlagConfig), in)
	}
	if err != nil {
		return app.failServer(mode, p.commandName(), err)
	}
	if mode == outputJSON {
		return app.renderQualification(p.commandName(), data)
	}
	switch d := data.(type) {
	case generated.NativeReport:
		_, err = fmt.Fprintf(app.stdout, "Native run %s: %d scenarios, %d pending requirements.\n", d.RunID, len(d.Scenarios), len(d.PendingRequirements))
	case generated.NativeStepResult:
		_, err = fmt.Fprintf(app.stdout, "Scenario %s step %d: %s.\n", d.Binding.ScenarioID, d.Binding.Ordinal, d.Status)
	}
	if err != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	return 0
}

// Local native work can mutate through approved guest plans. Preserve the
// measured aggregate instead of using the read-only local result helper.
func (app *App) renderQualification(command string, data any) int {
	raw, err := json.Marshal(data)
	if err != nil {
		return app.fail(outputJSON, command, generated.ErrorCodeIntegrityFailure, "output", generated.RunStatusFailed, false)
	}
	id, err := app.requestIDs()
	if err != nil || id == "" {
		return app.fail(outputJSON, command, generated.ErrorCodeIntegrityFailure, "request-id", generated.RunStatusFailed, true)
	}
	changed := false
	switch d := data.(type) {
	case generated.NativeReport:
		changed = d.Changed
	case generated.NativeStepResult:
		changed = d.Changed
	}
	envelope := generated.RunResult{Schema: generated.SchemaIDRunResult, SchemaVersion: generated.RegistrySchemaVersion, ToolVersion: app.build.ToolVersion, Command: command, RequestID: id, Status: generated.RunStatusSucceeded, Changed: changed, ReleaseBuildID: app.build.ReleaseBuildID, SourceRevision: app.build.SourceRevision, Errors: []generated.ResultError{}, Data: raw}
	if err = json.NewEncoder(app.stdout).Encode(envelope); err != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	return 0
}
