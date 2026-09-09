// Package cli implements the provider-neutral vsk-labs command surface from
// the generated registry. It does not own command metadata or runtime engines.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"runtime"
	"strconv"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/clientfile"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"github.com/vegastack/vegastack-labs/internal/release"
	"github.com/vegastack/vegastack-labs/internal/result"
)

const (
	fallbackRequestID = "request-id-unavailable"
)

var releaseErrorTargets = map[string]struct{}{
	"asset-digest": {}, "asset-file": {}, "asset-signature": {},
	"bundle-file": {}, "bundle-signature": {}, "context": {},
	"manifest": {}, "manifest-file": {}, "manifest-path": {}, "manifest-schema": {}, "manifest-signature": {},
	"platform": {}, "policy": {}, "policy-file": {}, "policy-schema": {}, "release-reference": {}, "selection": {},
}

type BuildInfo = result.BuildInfo

type RequestIDSource = result.RequestIDSource

type ReleaseOperations interface {
	Inspect(context.Context, release.InspectRequest) (generated.ReleaseInspectData, error)
	Verify(context.Context, release.VerifyRequest) (generated.ReleaseVerifyData, error)
}

type ServerOperations interface {
	Run(context.Context, string) error
	Status(context.Context, string) (localapi.Response, error)
}

type ControlOperations interface {
	Summary(context.Context, string) (localapi.TypedResponse[generated.ApiSummaryData], error)
	DatabaseStatus(context.Context, string) (localapi.TypedResponse[generated.DatabaseStatusData], error)
	ImportInventory(context.Context, string, generated.InventoryImportRequest) (localapi.TypedResponse[generated.InventoryImportData], error)
	DiffInventory(context.Context, string, generated.InventoryDiffRequest) (localapi.TypedResponse[generated.InventoryDiffData], error)
	ExportInventory(context.Context, string, generated.InventoryExportRequest) (localapi.TypedResponse[generated.InventoryExportData], error)
}

type Option func(*App)

func WithReleaseOperations(operations ReleaseOperations) Option {
	return func(app *App) {
		app.releases = operations
	}
}

func WithServerOperations(operations ServerOperations) Option {
	return func(app *App) {
		app.server = operations
	}
}

func WithControlOperations(operations ControlOperations, files clientfile.Reader) Option {
	return func(app *App) {
		app.control = operations
		app.files = files
	}
}

type App struct {
	stdout     io.Writer
	stderr     io.Writer
	build      BuildInfo
	requestIDs RequestIDSource
	releases   ReleaseOperations
	server     ServerOperations
	control    ControlOperations
	files      clientfile.Reader
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
	case generated.CommandNameServerRun:
		if app.server == nil {
			return app.fail(mode, parsed.commandName(), generated.ErrorCodeIntegrityFailure, "server-operations", generated.RunStatusFailed, false)
		}
		if err := app.server.Run(ctx, parsed.Value(generated.FlagConfig)); err != nil {
			return app.failServer(mode, parsed.commandName(), err)
		}
		return 0
	case generated.CommandNameServerStatus:
		if app.server == nil {
			return app.fail(mode, parsed.commandName(), generated.ErrorCodeIntegrityFailure, "server-operations", generated.RunStatusFailed, false)
		}
		response, err := app.server.Status(ctx, parsed.Value(generated.FlagConfig))
		if err != nil {
			return app.failServerStatus(mode, parsed.commandName(), err)
		}
		if mode == outputJSON {
			if _, err := app.stdout.Write(response.Raw); err != nil {
				return exitCodeFor(generated.ErrorCodeIntegrityFailure)
			}
			return response.ExitCode
		}
		return renderHumanServerStatus(app.stdout, response.Status, response.ExitCode)
	case generated.CommandNameStatus:
		if app.control == nil {
			return app.fail(mode, parsed.commandName(), generated.ErrorCodeIntegrityFailure, "control-operations", generated.RunStatusFailed, false)
		}
		response, err := app.control.Summary(ctx, parsed.Value(generated.FlagConfig))
		if err != nil {
			return app.failServer(mode, parsed.commandName(), err)
		}
		if response.ExitCode != 0 {
			return app.remoteFailure(mode, response.Raw, response.Result, response.ExitCode)
		}
		if mode == outputJSON {
			return writeRemoteJSON(app.stdout, response.Raw, response.ExitCode)
		}
		return renderHumanSummary(app.stdout, response.Data)
	case generated.CommandNameDatabaseStatus:
		if app.control == nil {
			return app.fail(mode, parsed.commandName(), generated.ErrorCodeIntegrityFailure, "control-operations", generated.RunStatusFailed, false)
		}
		response, err := app.control.DatabaseStatus(ctx, parsed.Value(generated.FlagConfig))
		if err != nil {
			return app.failServer(mode, parsed.commandName(), err)
		}
		if response.ExitCode != 0 {
			return app.remoteFailure(mode, response.Raw, response.Result, response.ExitCode)
		}
		if mode == outputJSON {
			return writeRemoteJSON(app.stdout, response.Raw, response.ExitCode)
		}
		return renderHumanDatabaseStatus(app.stdout, response.Data)
	case generated.CommandNameInventoryImport:
		if app.control == nil || app.files == nil {
			return app.fail(mode, parsed.commandName(), generated.ErrorCodeIntegrityFailure, "control-operations", generated.RunStatusFailed, false)
		}
		content, err := app.files.Read(ctx, parsed.Value(generated.FlagFile), clientfile.MaxInventoryBytes)
		if err != nil {
			return app.failServer(mode, parsed.commandName(), err)
		}
		var expected *int64
		if value := parsed.Value(generated.FlagExpectedStateRevision); value != "" {
			revision, _ := strconv.ParseInt(value, 10, 64)
			expected = &revision
		}
		response, err := app.control.ImportInventory(ctx, parsed.Value(generated.FlagConfig), generated.InventoryImportRequest{Format: parsed.Value(generated.FlagFormat), SourceRevision: parsed.Value(generated.FlagSourceRevision), CapturedAt: parsed.Value(generated.FlagCapturedAt), IdempotencyKey: parsed.Value(generated.FlagIdempotencyKey), ExpectedStateRevision: expected, Content: string(content)})
		if err != nil {
			return app.failServer(mode, parsed.commandName(), err)
		}
		if response.ExitCode != 0 {
			return app.remoteFailure(mode, response.Raw, response.Result, response.ExitCode)
		}
		if mode == outputJSON {
			return writeRemoteJSON(app.stdout, response.Raw, response.ExitCode)
		}
		return renderHumanInventoryImport(app.stdout, response.Data)
	case generated.CommandNameInventoryDiff:
		if app.control == nil {
			return app.fail(mode, parsed.commandName(), generated.ErrorCodeIntegrityFailure, "control-operations", generated.RunStatusFailed, false)
		}
		request := generated.InventoryDiffRequest{}
		if parsed.Value(generated.FlagDraftID) != "" {
			revision, _ := strconv.ParseInt(parsed.Value(generated.FlagDraftRevision), 10, 64)
			request.CandidateKind = "draft"
			request.Draft = &generated.InventoryDraftRef{DraftID: parsed.Value(generated.FlagDraftID), DraftRevision: revision}
		} else {
			if app.files == nil {
				return app.fail(mode, parsed.commandName(), generated.ErrorCodeIntegrityFailure, "control-operations", generated.RunStatusFailed, false)
			}
			content, err := app.files.Read(ctx, parsed.Value(generated.FlagFile), clientfile.MaxInventoryBytes)
			if err != nil {
				return app.failServer(mode, parsed.commandName(), err)
			}
			format, source, captured, body := parsed.Value(generated.FlagFormat), parsed.Value(generated.FlagSourceRevision), parsed.Value(generated.FlagCapturedAt), string(content)
			request = generated.InventoryDiffRequest{CandidateKind: "file", Format: &format, SourceRevision: &source, CapturedAt: &captured, Content: &body}
		}
		response, err := app.control.DiffInventory(ctx, parsed.Value(generated.FlagConfig), request)
		if err != nil {
			return app.failServer(mode, parsed.commandName(), err)
		}
		if response.ExitCode != 0 {
			return app.remoteFailure(mode, response.Raw, response.Result, response.ExitCode)
		}
		if mode == outputJSON {
			return writeRemoteJSON(app.stdout, response.Raw, response.ExitCode)
		}
		return renderHumanInventoryDiff(app.stdout, response.Data)
	case generated.CommandNameInventoryExport:
		if app.control == nil {
			return app.fail(mode, parsed.commandName(), generated.ErrorCodeIntegrityFailure, "control-operations", generated.RunStatusFailed, false)
		}
		revision, _ := strconv.ParseInt(parsed.Value(generated.FlagDraftRevision), 10, 64)
		response, err := app.control.ExportInventory(ctx, parsed.Value(generated.FlagConfig), generated.InventoryExportRequest{Draft: generated.InventoryDraftRef{DraftID: parsed.Value(generated.FlagDraftID), DraftRevision: revision}})
		if err != nil {
			return app.failServer(mode, parsed.commandName(), err)
		}
		if response.ExitCode != 0 {
			return app.remoteFailure(mode, response.Raw, response.Result, response.ExitCode)
		}
		if mode == outputJSON {
			return writeRemoteJSON(app.stdout, response.Raw, response.ExitCode)
		}
		return renderHumanInventoryExport(app.stdout, response.Data)
	default:
		return app.fail(mode, parsed.commandName(), generated.ErrorCodeIntegrityFailure, "command-registry", generated.RunStatusFailed, false)
	}
}

var serverErrorTargets = map[string]struct{}{
	"application-health": {}, "application-shutdown": {}, "application-start": {},
	"context": {}, "control-operations": {}, "control-service": {}, "control-service-drain": {}, "control-service-lock": {}, "control-service-request": {},
	"control-service-response": {}, "control-socket": {}, "control-socket-parent": {},
	"identity-header": {}, "local-peer": {}, "method": {}, "principal-bindings": {},
	"inventory-file": {}, "request-body": {}, "server-config": {}, "server-platform": {},
}

func writeRemoteJSON(output io.Writer, raw []byte, exitCode int) int {
	if _, err := output.Write(raw); err != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	return exitCode
}

func (app *App) remoteFailure(mode outputMode, raw []byte, envelope generated.RunResult, exitCode int) int {
	if mode == outputJSON {
		return writeRemoteJSON(app.stdout, raw, exitCode)
	}
	if len(envelope.Errors) != 1 {
		return renderHumanFailure(app.stderr, generated.ErrorCodeIntegrityFailure, "control-service-response", exitCodeFor(generated.ErrorCodeIntegrityFailure))
	}
	return renderHumanFailure(app.stderr, envelope.Errors[0].Code, envelope.Errors[0].Target, exitCode)
}

func (app *App) failServer(mode outputMode, command string, err error) int {
	stable, ok := failure.As(err)
	if !ok || stable.Target == "" {
		return app.fail(mode, command, generated.ErrorCodeIntegrityFailure, "server-operations", generated.RunStatusFailed, false)
	}
	if _, knownCode := generated.ErrorExitCodes[stable.Code]; !knownCode {
		return app.fail(mode, command, generated.ErrorCodeIntegrityFailure, "server-operations", generated.RunStatusFailed, false)
	}
	if _, safeTarget := serverErrorTargets[stable.Target]; !safeTarget {
		return app.fail(mode, command, generated.ErrorCodeIntegrityFailure, "server-operations", generated.RunStatusFailed, false)
	}
	status := generated.RunStatusFailed
	if stable.Code == generated.ErrorCodeInterrupted {
		status = generated.RunStatusInterrupted
	} else if stable.Code == generated.ErrorCodeDependencyUnavailable || stable.Code == generated.ErrorCodePrerequisiteBlocked {
		status = generated.RunStatusBlocked
	}
	return app.fail(mode, command, stable.Code, stable.Target, status, stable.Code == generated.ErrorCodeInterrupted)
}

func (app *App) failServerStatus(mode outputMode, command string, err error) int {
	stable, ok := failure.As(err)
	if ok && stable.Code == generated.ErrorCodeDependencyUnavailable && stable.Target == "control-service" {
		status := generated.ServerStatusData{State: "unavailable", ReadAvailable: false, MutationAvailable: false, RecoveryEpoch: 0, StateRevision: 0}
		if mode != outputJSON {
			return renderHumanServerStatus(app.stdout, status, generated.ErrorExitCodes[stable.Code])
		}
		factory := result.NewFactory(app.build, app.requestIDs)
		envelope, buildErr := factory.Failure(command, generated.RunStatusBlocked, stable.Code, stable.Target, true, 0, 0, status)
		if buildErr != nil {
			return app.fail(mode, command, generated.ErrorCodeIntegrityFailure, "request-id", generated.RunStatusFailed, true)
		}
		if encodeErr := result.Encode(app.stdout, envelope); encodeErr != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
		return generated.ErrorExitCodes[stable.Code]
	}
	return app.failServer(mode, command, err)
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
	if _, knownCode := generated.ErrorExitCodes[releaseErr.Code]; !knownCode {
		return app.fail(mode, command, generated.ErrorCodeIntegrityFailure, "release-verifier", generated.RunStatusFailed, false)
	}
	if _, safeTarget := releaseErrorTargets[releaseErr.Target]; !safeTarget {
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
