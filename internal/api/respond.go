package api

import (
	"bytes"
	"net/http"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/result"
)

const maxFiniteResponseBytes = 4 << 20
const MaxOperationResponseBytes = 24 << 20

func apiFailure(code, target string) error { return failure.New(code, target, false) }

func (app *Application) success(writer http.ResponseWriter, operation string, revision, epoch int64, data any) {
	envelope, err := app.config.Results.Success(operation, epoch, revision, data)
	if err != nil {
		app.failure(writer, operation, err)
		return
	}
	app.writeEnvelope(writer, operation, envelope, maxFiniteResponseBytes)
}

func (app *Application) operationSuccess(writer http.ResponseWriter, operation, requestID string, changed bool, revision, epoch int64, data any) {
	envelope, err := app.config.Results.SuccessWithRequestID(operation, requestID, changed, epoch, revision, data)
	if err != nil {
		app.failure(writer, operation, err)
		return
	}
	app.writeEnvelope(writer, operation, envelope, MaxOperationResponseBytes)
}

func (app *Application) writeEnvelope(writer http.ResponseWriter, operation string, envelope generated.RunResult, limit int) {
	var body bytes.Buffer
	if err := result.Encode(&body, envelope); err != nil || body.Len() > limit {
		app.failure(writer, operation, apiFailure(generated.ErrorCodeIntegrityFailure, "response"))
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(body.Bytes())
}

func (app *Application) operationFailure(writer http.ResponseWriter, operation, requestID string, cause error) {
	code, target, retryable := classifyOperationError(cause)
	statusName := generated.RunStatusFailed
	if code == generated.ErrorCodeInterrupted {
		statusName = generated.RunStatusInterrupted
	}
	envelope, err := app.config.Results.FailureWithRequestID(operation, requestID, statusName, code, target, retryable, 0, 0, struct{}{})
	if err != nil {
		app.failure(writer, operation, err)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(httpStatus(code))
	_ = result.Encode(writer, envelope)
}

func (app *Application) failure(writer http.ResponseWriter, operation string, cause error) {
	code := apiErrorCode(cause)
	if code == "" {
		code = generated.ErrorCodeDependencyUnavailable
	}
	status := httpStatus(code)
	if status == 0 {
		status = http.StatusServiceUnavailable
	}
	envelope, err := app.config.Results.Failure(operation, generated.RunStatusFailed, code, "read", false, 0, 0, struct{}{})
	if err != nil {
		http.Error(writer, "INTEGRITY_FAILURE", http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_ = result.Encode(writer, envelope)
}

func httpStatus(code string) int {
	return map[string]int{
		generated.ErrorCodeAuthenticationRequired: http.StatusUnauthorized,
		generated.ErrorCodeAuthorizationDenied:    http.StatusForbidden,
		generated.ErrorCodeInputInvalid:           http.StatusBadRequest,
		generated.ErrorCodeSchemaUnsupported:      http.StatusBadRequest,
		generated.ErrorCodeStateConflict:          http.StatusConflict,
		generated.ErrorCodeRecoveryEpochMismatch:  http.StatusConflict,
		generated.ErrorCodeResourceNotFound:       http.StatusNotFound,
		generated.ErrorCodePrerequisiteBlocked:    http.StatusPreconditionFailed,
		generated.ErrorCodeInterrupted:            http.StatusRequestTimeout,
		generated.ErrorCodeDependencyUnavailable:  http.StatusServiceUnavailable,
		generated.ErrorCodeIntegrityFailure:       http.StatusServiceUnavailable,
	}[code]
}
