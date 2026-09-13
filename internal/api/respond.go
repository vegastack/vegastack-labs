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

func (app *Application) operationRunSuccess(writer http.ResponseWriter, operation, requestID string, run generated.Run) {
	presentation := presentRun(run)
	envelope, err := app.config.Results.SuccessWithRequestID(operation, requestID, run.Changed, run.RecoveryEpoch, run.StateRevision, presentation)
	if err != nil {
		app.failure(writer, operation, err)
		return
	}
	envelope.RunID, envelope.PlanID = &run.RunID, &run.PlanID
	app.writeEnvelope(writer, operation, envelope, MaxOperationResponseBytes)
}

// executeRunResult projects the durable run rather than the transient call
// outcome. Exact retries must report the same terminal meaning, identity and
// revision even though no adapter is invoked on the replay.
func (app *Application) executeRunResult(writer http.ResponseWriter, operation, requestID string, run generated.Run, cause error) {
	// Durable terminal state is authoritative even when the submit call reports
	// an injected/transient error after the completed transition committed.
	if run.Status == generated.RunStatusSucceeded {
		app.operationRunSuccess(writer, operation, requestID, run)
		return
	}

	status, code, retryable := durableRunFailure(run.Status)
	presentation := presentRun(run)
	envelope, err := app.config.Results.FailureWithRequestID(operation, requestID, status, code, "run", retryable, run.RecoveryEpoch, run.StateRevision, presentation)
	if err != nil {
		app.failure(writer, operation, err)
		return
	}
	envelope.RunID, envelope.PlanID, envelope.Changed = &run.RunID, &run.PlanID, run.Changed
	var body bytes.Buffer
	if err := result.Encode(&body, envelope); err != nil || body.Len() > MaxOperationResponseBytes {
		app.failure(writer, operation, apiFailure(generated.ErrorCodeIntegrityFailure, "response"))
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(httpStatus(code))
	_, _ = writer.Write(body.Bytes())
}

// presentRun is the server-owned interpretation of durable execution state.
// Operator clients render these exact facts and never infer workflow advice.
func presentRun(run generated.Run) generated.RunPresentation {
	steps := make([]generated.BrowserRunStep, 0, len(run.Steps))
	completed := make([]generated.BrowserRunStep, 0, len(run.Steps))
	incomplete := make([]generated.BrowserRunStep, 0, len(run.Steps))
	for _, step := range run.Steps {
		projected := generated.BrowserRunStep{Sequence: step.Sequence, OperationID: step.OperationID, OperationType: step.OperationType, TargetID: step.TargetID, StepID: step.StepID, Status: step.Status}
		steps = append(steps, projected)
		switch step.Status {
		case generated.RunStatusSucceeded, generated.RunStatusFailed, generated.RunStatusCancelled:
			completed = append(completed, projected)
		default:
			incomplete = append(incomplete, projected)
		}
	}
	next := "inspect the durable run"
	if run.Status == generated.RunStatusPartial || run.RollbackStatus == "required" || run.VerificationStatus == "incomplete" {
		next = "recovery required; inspect the durable run"
	} else {
		switch run.Status {
		case generated.RunStatusSucceeded:
			next = "none; execution completed"
		case generated.RunStatusCancelled:
			next = "inspect before creating another plan"
		case generated.RunStatusInterrupted:
			next = "inspect, then resume or cancel through the server"
		case "queued", "running":
			next = "inspect or cancel through the server"
		}
	}
	browserRun := generated.BrowserRun{
		Schema: generated.SchemaIDBrowserRun, SchemaVersion: "1.0.0",
		RunID: run.RunID, PlanID: run.PlanID, PlanDigest: run.PlanDigest,
		Status: run.Status, Steps: steps, CancellationRequested: run.CancellationRequested,
		RollbackStatus: run.RollbackStatus, VerificationStatus: run.VerificationStatus, VerificationDigest: run.VerificationDigest,
		Changed: run.Changed, StateRevision: run.StateRevision, RecoveryEpoch: run.RecoveryEpoch,
		CreatedAt: run.CreatedAt, UpdatedAt: run.UpdatedAt, Extensions: append([]generated.ContractExtension(nil), run.Extensions...),
	}
	return generated.RunPresentation{Run: browserRun, CompletedWork: completed, IncompleteWork: incomplete, NextSafeAction: next}
}

func durableRunFailure(status string) (string, string, bool) {
	switch status {
	case generated.RunStatusFailed:
		return generated.RunStatusFailed, generated.ErrorCodeExecutionFailed, false
	case generated.RunStatusPartial:
		return generated.RunStatusPartial, generated.ErrorCodeRecoveryRequired, false
	case generated.RunStatusInterrupted:
		return generated.RunStatusInterrupted, generated.ErrorCodeInterrupted, true
	case generated.RunStatusCancelled:
		return generated.RunStatusCancelled, generated.ErrorCodeInterrupted, false
	default:
		return generated.RunStatusBlocked, generated.ErrorCodeStateConflict, false
	}
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
	if code == generated.ErrorCodeExecutionPartial || code == generated.ErrorCodeRecoveryRequired {
		statusName = generated.RunStatusPartial
	} else if code == generated.ErrorCodeInterrupted {
		statusName = generated.RunStatusInterrupted
	}
	envelope, err := app.config.Results.FailureWithRequestID(operation, requestID, statusName, code, target, retryable, 0, 0, struct{}{})
	if err != nil {
		app.failure(writer, operation, err)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	status := httpStatus(code)
	if status == 0 {
		status = http.StatusServiceUnavailable
	}
	writer.WriteHeader(status)
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
		generated.ErrorCodeApprovalRequired:       http.StatusPreconditionFailed,
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
		generated.ErrorCodePlanStale:              http.StatusConflict,
		generated.ErrorCodeExecutionFailed:        http.StatusBadGateway,
		generated.ErrorCodeExecutionPartial:       http.StatusConflict,
		generated.ErrorCodeRecoveryRequired:       http.StatusConflict,
	}[code]
}
