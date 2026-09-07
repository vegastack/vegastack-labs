// Package cli implements the provider-neutral vsk-labs command surface from
// the generated registry. It does not own command metadata or runtime engines.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

const (
	fallbackRequestID = "request-id-unavailable"
)

type BuildInfo struct {
	ToolVersion    string
	ReleaseBuildID string
	SourceRevision *string
}

type RequestIDSource func() (string, error)

type App struct {
	stdout     io.Writer
	stderr     io.Writer
	build      BuildInfo
	requestIDs RequestIDSource
}

func New(stdout, stderr io.Writer, build BuildInfo, requestIDs RequestIDSource) *App {
	if requestIDs == nil {
		requestIDs = func() (string, error) { return "", errors.New("request ID source unavailable") }
	}
	if build.SourceRevision != nil {
		revision := *build.SourceRevision
		build.SourceRevision = &revision
	}
	return &App{stdout: stdout, stderr: stderr, build: build, requestIDs: requestIDs}
}

func (app *App) Run(ctx context.Context, args []string) int {
	mode := requestedOutput(args)
	if err := ctx.Err(); err != nil {
		return app.fail(mode, "", generated.ErrorCodeInterrupted, "context", generated.RunStatusCancelled, true)
	}

	parsed, parseFailure := parseArguments(args)
	if parseFailure != nil {
		return app.fail(mode, parsed.commandName(), parseFailure.code, parseFailure.target, generated.RunStatusFailed, false)
	}
	mode = parsed.output
	if parsed.command.Availability == generated.AvailabilityPlanned {
		return app.fail(mode, parsed.commandName(), generated.ErrorCodePrerequisiteBlocked, "command", generated.RunStatusBlocked, false)
	}

	switch parsed.commandName() {
	case generated.CommandNameHelp:
		if mode == outputJSON {
			data, err := json.Marshal(struct {
				Commands []generated.Command `json:"commands"`
			}{Commands: generated.Commands})
			if err != nil {
				return app.fail(mode, parsed.commandName(), generated.ErrorCodeIntegrityFailure, "output", generated.RunStatusFailed, false)
			}
			return app.succeedJSON(parsed.commandName(), data)
		}
		return renderHumanHelp(app.stdout)
	case generated.CommandNameVersion:
		if mode == outputJSON {
			return app.succeedJSON(parsed.commandName(), json.RawMessage("{}"))
		}
		return renderHumanVersion(app.stdout, app.build)
	default:
		return app.fail(mode, parsed.commandName(), generated.ErrorCodeIntegrityFailure, "command-registry", generated.RunStatusFailed, false)
	}
}

func (app *App) succeedJSON(command string, data json.RawMessage) int {
	requestID, err := app.requestIDs()
	if err != nil || requestID == "" {
		return app.renderJSON(fallbackRequestID, command, generated.RunStatusFailed, []generated.ResultError{{
			Code: generated.ErrorCodeIntegrityFailure, Target: "request-id", Retryable: false,
		}}, json.RawMessage("{}"))
	}
	return app.renderJSON(requestID, command, generated.RunStatusSucceeded, []generated.ResultError{}, data)
}

func (app *App) fail(mode outputMode, command, code, target, status string, preserveCodeOnRequestIDFailure bool) int {
	exitCode := exitCode(code)
	if mode != outputJSON {
		return renderHumanFailure(app.stderr, code, target, exitCode)
	}

	requestID, err := app.requestIDs()
	if err != nil || requestID == "" {
		requestID = fallbackRequestID
		if !preserveCodeOnRequestIDFailure {
			code = generated.ErrorCodeIntegrityFailure
			target = "request-id"
			status = generated.RunStatusFailed
			exitCode = exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
	}
	return app.renderJSON(requestID, command, status, []generated.ResultError{{
		Code: code, Target: target, Retryable: false,
	}}, json.RawMessage("{}"))
}

func (app *App) renderJSON(requestID, command, status string, resultErrors []generated.ResultError, data json.RawMessage) int {
	result := generated.RunResult{
		Schema:         generated.SchemaIDRunResult,
		SchemaVersion:  generated.RegistrySchemaVersion,
		ToolVersion:    app.build.ToolVersion,
		Command:        command,
		RequestID:      requestID,
		Status:         status,
		Changed:        false,
		RecoveryEpoch:  0,
		StateRevision:  0,
		ReleaseBuildID: app.build.ReleaseBuildID,
		SourceRevision: app.build.SourceRevision,
		Errors:         resultErrors,
		Data:           data,
	}
	if err := json.NewEncoder(app.stdout).Encode(result); err != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	if len(resultErrors) == 0 {
		return 0
	}
	return exitCodeFor(resultErrors[0].Code)
}

func exitCode(code string) int {
	return exitCodeFor(code)
}

func exitCodeFor(code string) int {
	if value, ok := generated.ErrorExitCodes[code]; ok {
		return value
	}
	return generated.ErrorExitCodes[generated.ErrorCodeIntegrityFailure]
}

func requestedOutput(args []string) outputMode {
	for index := 0; index+1 < len(args); index++ {
		if args[index] == generated.FlagOutput && args[index+1] == generated.OutputJSON {
			return outputJSON
		}
	}
	return outputHuman
}

func commandName(path []string) string {
	return strings.Join(path, " ")
}
