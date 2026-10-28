package cli

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/result"
)

// doctor uses the existing authenticated summary read. It performs no provider
// refresh, draft construction, SQLite access or mutation qualification.
func (app *App) doctor(ctx context.Context, parsed parsedArguments) int {
	if app.control == nil {
		return app.doctorFailure(parsed, generated.ErrorCodePrerequisiteBlocked)
	}
	response, err := app.control.Summary(ctx, parsed.Value(generated.FlagConfig))
	if err != nil {
		code := generated.ErrorCodeIntegrityFailure
		if stable, ok := failure.As(err); ok {
			if _, known := generated.ErrorExitCodes[stable.Code]; known {
				code = stable.Code
			}
		}
		return app.doctorFailure(parsed, code)
	}
	if response.ExitCode != 0 {
		code := generated.ErrorCodeIntegrityFailure
		if len(response.Result.Errors) > 0 {
			if _, known := generated.ErrorExitCodes[response.Result.Errors[0].Code]; known {
				code = response.Result.Errors[0].Code
			}
		}
		return app.doctorFailure(parsed, code)
	}
	code, invariant, next := diagnoseSummary(response.Data)
	envelope := response.Result
	envelope.Command = parsed.commandName()
	envelope.Changed = false
	envelope.RunID, envelope.PlanID = nil, nil
	envelope.Errors = []generated.ResultError{}
	envelope.Data, err = json.Marshal(response.Data)
	if err != nil {
		return app.doctorFailure(parsed, generated.ErrorCodeIntegrityFailure)
	}
	envelope.Status = generated.RunStatusSucceeded
	if code != "" {
		envelope.Status = generated.RunStatusBlocked
		envelope.Errors = []generated.ResultError{{Code: code, Target: invariant, Retryable: false}}
	}
	exit := 0
	if code != "" {
		exit = generated.ErrorExitCodes[code]
	}
	if parsed.output == outputJSON {
		if err := result.Encode(app.stdout, envelope); err != nil {
			return generated.ErrorExitCodes[generated.ErrorCodeIntegrityFailure]
		}
		return exit
	}
	if _, err := fmt.Fprintf(app.stdout, "Doctor: %s\nNext: %s\nState revision %d\nRecovery epoch %d\n", invariant, next, response.Data.StateRevision, response.Data.RecoveryEpoch); err != nil {
		return generated.ErrorExitCodes[generated.ErrorCodeIntegrityFailure]
	}
	return exit
}

func (app *App) doctorFailure(parsed parsedArguments, code string) int {
	if parsed.output == outputJSON {
		return app.fail(outputJSON, parsed.commandName(), code, "doctor-summary", generated.RunStatusBlocked, false)
	}
	next := "Check the protected profile and control-service availability; preserve sanitized diagnostics."
	if code == generated.ErrorCodeAuthorizationDenied || code == generated.ErrorCodeAuthenticationRequired || code == generated.ErrorCodeSessionExpired {
		next = "Ask the responsible human to restore the existing scoped authentication or read grant."
	}
	if _, err := fmt.Fprintf(app.stdout, "Doctor: %s\nNext: %s\n", code, next); err != nil {
		return generated.ErrorExitCodes[generated.ErrorCodeIntegrityFailure]
	}
	return generated.ErrorExitCodes[code]
}
func diagnoseSummary(data generated.ApiSummaryData) (string, string, string) {
	if data.DatabaseMode != "ready" {
		return generated.ErrorCodeIntegrityFailure, "database-mode", "Preserve the database and audit evidence; follow the existing integrity/recovery runbook."
	}
	if !data.ReadAvailable {
		return generated.ErrorCodePrerequisiteBlocked, "read-unavailable", "Restore the existing scoped read capability before further diagnosis."
	}
	switch data.WorstSourceState {
	case "healthy":
		return "", "summary-healthy", "Inspect the exact operation's gates and current evidence; summary health is not workload admission or apply authorization."
	case "stale":
		return generated.ErrorCodeEvidenceExpired, "source-stale", "Use the owning approved observation workflow to refresh stale evidence before admission or change."
	case "failed":
		return generated.ErrorCodeDependencyUnavailable, "source-failed", "Inspect the failing source through its owning diagnosis and recovery workflow."
	case "unavailable":
		return generated.ErrorCodeDependencyUnavailable, "source-unavailable", "Restore the owning source dependency through its existing authorized workflow."
	default:
		return generated.ErrorCodePrerequisiteBlocked, "source-unknown", "Collect current evidence through the owning approved observation workflow; do not infer health."
	}
}
