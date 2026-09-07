// Package cli implements the provider-neutral vsk-labs command surface from
// the generated registry. It does not own command metadata or runtime engines.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"runtime"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/release"
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

type ReleaseOperations interface {
	Inspect(context.Context, release.InspectRequest) (generated.ReleaseInspectData, error)
	Verify(context.Context, release.VerifyRequest) (generated.ReleaseVerifyData, error)
}

type Option func(*App)

func WithReleaseOperations(operations ReleaseOperations) Option {
	return func(app *App) {
		app.releases = operations
	}
}

type App struct {
	stdout     io.Writer
	stderr     io.Writer
	build      BuildInfo
	requestIDs RequestIDSource
	releases   ReleaseOperations
}

func New(stdout, stderr io.Writer, build BuildInfo, requestIDs RequestIDSource, options ...Option) *App {
	if requestIDs == nil {
		requestIDs = func() (string, error) { return "", errors.New("request ID source unavailable") }
	}
	if build.SourceRevision != nil {
		revision := *build.SourceRevision
		build.SourceRevision = &revision
	}
	app := &App{stdout: stdout, stderr: stderr, build: build, requestIDs: requestIDs}
	for _, option := range options {
		if option != nil {
			option(app)
		}
	}
	return app
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
	case generated.CommandNameReleaseInspect:
		if app.releases == nil {
			return app.fail(mode, parsed.commandName(), generated.ErrorCodeIntegrityFailure, "release-verifier", generated.RunStatusFailed, false)
		}
		data, err := app.releases.Inspect(ctx, release.InspectRequest{
			ManifestPath: parsed.Value(generated.FlagManifest),
			Platform:     release.Platform{OS: runtime.GOOS, Architecture: runtime.GOARCH, SchemaMajor: generated.SchemaMajor},
		})
		if err != nil {
			return app.failRelease(mode, parsed.commandName(), err)
		}
		if mode == outputJSON {
			return app.succeedData(parsed.commandName(), data)
		}
		return renderHumanReleaseInspect(app.stdout, data)
	case generated.CommandNameReleaseVerify:
		if app.releases == nil {
			return app.fail(mode, parsed.commandName(), generated.ErrorCodeIntegrityFailure, "release-verifier", generated.RunStatusFailed, false)
		}
		data, err := app.releases.Verify(ctx, release.VerifyRequest{
			ManifestPath: parsed.Value(generated.FlagManifest),
			PolicyPath:   parsed.Value(generated.FlagPolicy),
			Selection:    release.Selection{All: parsed.Switch(generated.FlagAll), AssetIDs: parsed.Values(generated.FlagAsset)},
		})
		if err != nil {
			return app.failRelease(mode, parsed.commandName(), err)
		}
		if mode == outputJSON {
			return app.succeedData(parsed.commandName(), data)
		}
		return renderHumanReleaseVerify(app.stdout, data)
	default:
		return app.fail(mode, parsed.commandName(), generated.ErrorCodeIntegrityFailure, "command-registry", generated.RunStatusFailed, false)
	}
}

func (app *App) succeedData(command string, data any) int {
	raw, err := json.Marshal(data)
	if err != nil {
		return app.fail(outputJSON, command, generated.ErrorCodeIntegrityFailure, "output", generated.RunStatusFailed, false)
	}
	return app.succeedJSON(command, raw)
}

func (app *App) failRelease(mode outputMode, command string, err error) int {
	var releaseErr *release.Error
	if !errors.As(err, &releaseErr) || releaseErr.Code == "" || releaseErr.Target == "" {
		return app.fail(mode, command, generated.ErrorCodeIntegrityFailure, "release-verifier", generated.RunStatusFailed, false)
	}
	status := generated.RunStatusFailed
	if releaseErr.Code == generated.ErrorCodeInterrupted {
		status = generated.RunStatusCancelled
	} else if releaseErr.Code == generated.ErrorCodePrerequisiteBlocked {
		status = generated.RunStatusBlocked
	}
	return app.fail(mode, command, releaseErr.Code, releaseErr.Target, status, false)
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
