// Package result creates the single generated machine-result envelope.
package result

import (
	"encoding/json"
	"errors"
	"io"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

type BuildInfo struct {
	ToolVersion    string
	ReleaseBuildID string
	SourceRevision *string
}

type RequestIDSource func() (string, error)

type Factory struct {
	build      BuildInfo
	requestIDs RequestIDSource
}

func NewFactory(build BuildInfo, requestIDs RequestIDSource) *Factory {
	if requestIDs == nil {
		requestIDs = func() (string, error) { return "", errors.New("request ID source unavailable") }
	}
	if build.SourceRevision != nil {
		revision := *build.SourceRevision
		build.SourceRevision = &revision
	}
	return &Factory{build: build, requestIDs: requestIDs}
}

func (factory *Factory) Success(command string, recoveryEpoch, stateRevision int64, data any) (generated.RunResult, error) {
	return factory.buildResult(command, generated.RunStatusSucceeded, nil, recoveryEpoch, stateRevision, data)
}

func (factory *Factory) Failure(command, status, code, target string, retryable bool, recoveryEpoch, stateRevision int64, data any) (generated.RunResult, error) {
	if _, ok := generated.ErrorExitCodes[code]; !ok || target == "" {
		return generated.RunResult{}, failure.New(generated.ErrorCodeIntegrityFailure, "result-error", false)
	}
	return factory.buildResult(command, status, []generated.ResultError{{Code: code, Target: target, Retryable: retryable}}, recoveryEpoch, stateRevision, data)
}

func (factory *Factory) buildResult(command, status string, resultErrors []generated.ResultError, recoveryEpoch, stateRevision int64, data any) (generated.RunResult, error) {
	requestID, err := factory.requestIDs()
	if err != nil || requestID == "" {
		return generated.RunResult{}, failure.New(generated.ErrorCodeIntegrityFailure, "request-id", false)
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return generated.RunResult{}, failure.New(generated.ErrorCodeIntegrityFailure, "result-data", false)
	}
	if resultErrors == nil {
		resultErrors = []generated.ResultError{}
	}
	return generated.RunResult{
		Schema: generated.SchemaIDRunResult, SchemaVersion: generated.RegistrySchemaVersion,
		ToolVersion: factory.build.ToolVersion, Command: command, RequestID: requestID,
		Status: status, Changed: false, RecoveryEpoch: recoveryEpoch, StateRevision: stateRevision,
		ReleaseBuildID: factory.build.ReleaseBuildID, SourceRevision: factory.build.SourceRevision,
		Errors: resultErrors, Data: json.RawMessage(raw),
	}, nil
}

func Encode(writer io.Writer, value generated.RunResult) error {
	return json.NewEncoder(writer).Encode(value)
}
