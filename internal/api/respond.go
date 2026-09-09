package api

import (
	"bytes"
	"net/http"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/result"
)

const maxFiniteResponseBytes = 4 << 20

func apiFailure(code, target string) error { return failure.New(code, target, false) }

func (app *Application) success(writer http.ResponseWriter, operation string, revision, epoch int64, data any) {
	envelope, err := app.config.Results.Success(operation, epoch, revision, data)
	if err != nil {
		app.failure(writer, operation, err)
		return
	}
	var body bytes.Buffer
	if err := result.Encode(&body, envelope); err != nil || body.Len() > maxFiniteResponseBytes {
		app.failure(writer, operation, apiFailure(generated.ErrorCodeIntegrityFailure, "response"))
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(body.Bytes())
}

func (app *Application) failure(writer http.ResponseWriter, operation string, cause error) {
	code := apiErrorCode(cause)
	if code == "" {
		code = generated.ErrorCodeDependencyUnavailable
	}
	status := map[string]int{
		generated.ErrorCodeAuthenticationRequired: http.StatusUnauthorized,
		generated.ErrorCodeAuthorizationDenied:    http.StatusForbidden,
		generated.ErrorCodeInputInvalid:           http.StatusBadRequest,
		generated.ErrorCodeSchemaUnsupported:      http.StatusBadRequest,
		generated.ErrorCodeStateConflict:          http.StatusConflict,
		generated.ErrorCodeResourceNotFound:       http.StatusNotFound,
		generated.ErrorCodeDependencyUnavailable:  http.StatusServiceUnavailable,
		generated.ErrorCodeIntegrityFailure:       http.StatusServiceUnavailable,
	}[code]
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
