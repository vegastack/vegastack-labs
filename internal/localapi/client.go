package localapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localtransport"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/runprotocol"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/sshtransport"
)

const (
	maxResponseBodyBytes          = 64 * 1024
	maxOperationResponseBodyBytes = 24 << 20
	maxOperationRequestBodyBytes  = 8 << 20
	statusTimeout                 = 3 * time.Second
	operationTimeout              = 30 * time.Second
)

// UncertainRunError means a mutating request disconnected and the one allowed
// durable-run inspection could not establish the result. It preserves the
// server-owned run address without inviting a resubmission.
type UncertainRunError struct {
	RunID string
	err   error
}

func NewUncertainRunError(runID string, cause error) error {
	return &UncertainRunError{RunID: runID, err: cause}
}

func (err *UncertainRunError) Error() string { return err.err.Error() }
func (err *UncertainRunError) Unwrap() error { return err.err }

func AsUncertainRun(err error) (*UncertainRunError, bool) {
	var uncertain *UncertainRunError
	ok := errors.As(err, &uncertain)
	return uncertain, ok
}

type Response struct {
	Raw      []byte
	Result   generated.RunResult
	Status   generated.ServerStatusData
	ExitCode int
}

type TypedResponse[T any] struct {
	Raw      []byte
	Result   generated.RunResult
	Data     T
	ExitCode int
}

type Client interface {
	CreateCredentialLifecycleDraft(context.Context, serverconfig.Profile, generated.CredentialLifecycleRequest) (TypedResponse[generated.CredentialLifecycleSubmission], error)
	ImportCredential(context.Context, serverconfig.Profile, generated.CredentialImportRequest, io.Reader) (TypedResponse[generated.CredentialImportSubmission], error)
	Gates(context.Context, serverconfig.Profile) (TypedResponse[generated.GateListData], error)
	GetGate(context.Context, serverconfig.Profile, string) (TypedResponse[generated.GateView], error)
	CheckGate(context.Context, serverconfig.Profile, string, string) (TypedResponse[generated.GateEvaluation], error)
	SubmitGateEvidence(context.Context, serverconfig.Profile, generated.GateEvidenceRequest) (TypedResponse[generated.GateEvidenceSubmission], error)
	SubmitProfileDraft(context.Context, serverconfig.Profile, generated.GateProfileDraftRequest) (TypedResponse[generated.GateProfileDraftSubmission], error)
	SubmitBackupPolicyDraft(context.Context, serverconfig.Profile, generated.BackupPolicyDraftRequest) (TypedResponse[generated.BackupPolicyDraftSubmission], error)
	SubmitBackupRetentionLockDraft(context.Context, serverconfig.Profile, generated.BackupRetentionLockDraftRequest) (TypedResponse[generated.BackupRetentionLockDraftSubmission], error)
	SubmitBackupRetirementDraft(context.Context, serverconfig.Profile, generated.BackupRetirementDraftRequest) (TypedResponse[generated.BackupRetirementDraftSubmission], error)
	BackupStatus(context.Context, serverconfig.Profile) (TypedResponse[generated.BackupStatusData], error)
	RunBackup(context.Context, serverconfig.Profile, generated.BackupRunRequest) (TypedResponse[generated.BackupJob], error)
	VerifyBackup(context.Context, serverconfig.Profile, generated.BackupVerifyRequest) (TypedResponse[generated.BackupJob], error)
	PlanRestore(context.Context, serverconfig.Profile, generated.RestoreRequest) (TypedResponse[generated.RestoreBinding], error)
	RunRestore(context.Context, serverconfig.Profile, generated.RestoreRunRequest) (TypedResponse[generated.RestoreBinding], error)
	VerifyRestore(context.Context, serverconfig.Profile, generated.RestoreVerifyRequest) (TypedResponse[generated.RestoreVerification], error)
	GetRestore(context.Context, serverconfig.Profile, string) (TypedResponse[generated.BrowserRestoreStatus], error)
	Status(context.Context, serverconfig.Profile) (Response, error)
	Summary(context.Context, serverconfig.Profile) (TypedResponse[generated.ApiSummaryData], error)
	DatabaseStatus(context.Context, serverconfig.Profile) (TypedResponse[generated.DatabaseStatusData], error)
	AuditCheckpoints(context.Context, serverconfig.Profile) (TypedResponse[generated.AuditCheckpointListData], error)
	VerifyAudit(context.Context, serverconfig.Profile) (TypedResponse[generated.AuditVerificationData], error)
	ImportInventory(context.Context, serverconfig.Profile, generated.InventoryImportRequest) (TypedResponse[generated.InventoryImportData], error)
	DiffInventory(context.Context, serverconfig.Profile, generated.InventoryDiffRequest) (TypedResponse[generated.InventoryDiffData], error)
	ExportInventory(context.Context, serverconfig.Profile, generated.InventoryExportRequest) (TypedResponse[generated.InventoryExportData], error)
	Plan(context.Context, serverconfig.Profile, string, int64) (TypedResponse[generated.Plan], error)
	Apply(context.Context, serverconfig.Profile, string) (TypedResponse[generated.RunPresentation], error)
	InspectRun(context.Context, serverconfig.Profile, string) (TypedResponse[generated.RunPresentation], error)
	CancelRun(context.Context, serverconfig.Profile, string) (TypedResponse[generated.RunPresentation], error)
	ResumeRun(context.Context, serverconfig.Profile, string) (TypedResponse[generated.RunPresentation], error)
}

type client struct{ results *result.Factory }

type requestSpec struct {
	method        localtransport.Method
	path, command string
	responseLimit int64
	timeout       time.Duration
	allowChanged  bool
}

func NewClient(results *result.Factory) Client { return &client{results: results} }

func (client *client) Status(ctx context.Context, profile serverconfig.Profile) (Response, error) {
	typed, err := requestTyped(client, ctx, profile, requestSpec{localtransport.MethodGet, "/api/v1/health", generated.CommandNameServerStatus, maxResponseBodyBytes, statusTimeout, false}, nil, validRemoteStatus)
	if err != nil {
		return Response{}, err
	}
	return Response{Raw: typed.Raw, Result: typed.Result, Status: typed.Data, ExitCode: typed.ExitCode}, nil
}

func (client *client) Summary(ctx context.Context, profile serverconfig.Profile) (TypedResponse[generated.ApiSummaryData], error) {
	return requestTyped(client, ctx, profile, requestSpec{localtransport.MethodGet, "/api/v1/summary", "api.v1.summary.get", maxResponseBodyBytes, statusTimeout, false}, nil, validSummary)
}

func (client *client) DatabaseStatus(ctx context.Context, profile serverconfig.Profile) (TypedResponse[generated.DatabaseStatusData], error) {
	return requestTyped(client, ctx, profile, requestSpec{localtransport.MethodGet, "/api/v1/database/status", "api.v1.database-status.get", maxResponseBodyBytes, statusTimeout, false}, nil, validDatabaseStatus)
}

func (client *client) ImportInventory(ctx context.Context, profile serverconfig.Profile, input generated.InventoryImportRequest) (TypedResponse[generated.InventoryImportData], error) {
	return requestTyped(client, ctx, profile, requestSpec{localtransport.MethodPost, "/api/v1/inventory-drafts/import", "api.v1.inventory-drafts.import", maxOperationResponseBodyBytes, operationTimeout, true}, input, validImportData)
}

func (client *client) DiffInventory(ctx context.Context, profile serverconfig.Profile, input generated.InventoryDiffRequest) (TypedResponse[generated.InventoryDiffData], error) {
	return requestTyped(client, ctx, profile, requestSpec{localtransport.MethodPost, "/api/v1/inventory-diffs", "api.v1.inventory-diffs.create", maxOperationResponseBodyBytes, operationTimeout, false}, input, validDiffData)
}

func (client *client) ExportInventory(ctx context.Context, profile serverconfig.Profile, input generated.InventoryExportRequest) (TypedResponse[generated.InventoryExportData], error) {
	return requestTyped(client, ctx, profile, requestSpec{localtransport.MethodPost, "/api/v1/inventory-exports", "api.v1.inventory-exports.create", maxOperationResponseBodyBytes, operationTimeout, true}, input, validExportData)
}

func (client *client) Plan(ctx context.Context, profile serverconfig.Profile, declarationID string, revision int64) (TypedResponse[generated.Plan], error) {
	var zero TypedResponse[generated.Plan]
	if !validPathToken(declarationID) || revision < 1 {
		return zero, failure.New(generated.ErrorCodeInputInvalid, "control-service-request", false)
	}
	base := "/api/v1/declarations/" + declarationID + "/revisions/" + strconv.FormatInt(revision, 10)
	prepared, err := requestTyped(client, ctx, profile, requestSpec{localtransport.MethodGet, base + "/plan-preparation", "api.v1.declarations.plan-preparation.get", maxOperationResponseBodyBytes, operationTimeout, false}, nil, validPlanPreparation)
	if err != nil {
		return zero, err
	}
	if prepared.ExitCode != 0 {
		return remapResponse[generated.Plan](prepared), nil
	}
	key, err := client.results.RequestID()
	if err != nil {
		return zero, err
	}
	input := generated.PlanCreateRequest{Schema: generated.SchemaIDPlanCreateRequest, SchemaVersion: "1.0.0", DeclarationID: declarationID, DeclarationRevision: revision, ExpectedStateRevision: prepared.Data.ExpectedStateRevision, RecoveryEpoch: prepared.Data.RecoveryEpoch, ObservationFingerprint: prepared.Data.ObservationFingerprint, IdempotencyKey: key, Extensions: []generated.ContractExtension{}}
	presented, err := requestTyped(client, ctx, profile, requestSpec{localtransport.MethodPost, "/api/v1/declarations/" + declarationID + "/plans", "api.v1.plans.create", maxOperationResponseBodyBytes, operationTimeout, true}, input, validPlanPresentation)
	if err != nil {
		return zero, err
	}
	return TypedResponse[generated.Plan]{Raw: presented.Raw, Result: presented.Result, Data: presented.Data.Plan, ExitCode: presented.ExitCode}, nil
}

func (client *client) Apply(ctx context.Context, profile serverconfig.Profile, planID string) (TypedResponse[generated.RunPresentation], error) {
	var zero TypedResponse[generated.RunPresentation]
	planResponse, err := client.getPlan(ctx, profile, planID)
	if err != nil {
		return zero, err
	}
	if planResponse.ExitCode != 0 {
		return remapResponse[generated.RunPresentation](planResponse), nil
	}
	key, err := client.results.RequestID()
	if err != nil {
		return zero, err
	}
	runID := runprotocol.ID(planID, key)
	input := generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: planID, PlanDigest: planResponse.Data.PlanDigest, RecoveryEpoch: planResponse.Data.Binding.RecoveryEpoch, IdempotencyKey: key, Extensions: []generated.ContractExtension{}}
	response, err := requestTyped(client, ctx, profile, requestSpec{localtransport.MethodPost, "/api/v1/plans/" + planID + "/execute", "api.v1.plans.execute", maxOperationResponseBodyBytes, operationTimeout, true}, input, validRunPresentation)
	if err == nil {
		return response, nil
	}
	inspected, inspectErr := client.InspectRun(context.WithoutCancel(ctx), profile, runID)
	if inspectErr == nil && inspected.ExitCode == 0 {
		return inspected, nil
	}
	return zero, NewUncertainRunError(runID, err)
}

func (client *client) InspectRun(ctx context.Context, profile serverconfig.Profile, runID string) (TypedResponse[generated.RunPresentation], error) {
	if !validPathToken(runID) {
		return TypedResponse[generated.RunPresentation]{}, failure.New(generated.ErrorCodeInputInvalid, "control-service-request", false)
	}
	return requestTyped(client, ctx, profile, requestSpec{localtransport.MethodGet, "/api/v1/runs/" + runID, "api.v1.runs.get", maxOperationResponseBodyBytes, operationTimeout, false}, nil, validRunPresentation)
}

func (client *client) CancelRun(ctx context.Context, profile serverconfig.Profile, runID string) (TypedResponse[generated.RunPresentation], error) {
	return client.mutateRun(ctx, profile, runID, false)
}

func (client *client) ResumeRun(ctx context.Context, profile serverconfig.Profile, runID string) (TypedResponse[generated.RunPresentation], error) {
	return client.mutateRun(ctx, profile, runID, true)
}

func (client *client) mutateRun(ctx context.Context, profile serverconfig.Profile, runID string, resume bool) (TypedResponse[generated.RunPresentation], error) {
	current, err := client.InspectRun(ctx, profile, runID)
	if err != nil || current.ExitCode != 0 {
		return current, err
	}
	key, err := client.results.RequestID()
	if err != nil {
		return TypedResponse[generated.RunPresentation]{}, err
	}
	action, command := "cancel", "api.v1.runs.cancel"
	if resume {
		action, command = "resume", "api.v1.runs.resume"
	}
	input := generated.RunReferenceRequest{Schema: generated.SchemaIDRunReferenceRequest, SchemaVersion: "1.0.0", RunID: runID, IdempotencyKey: key, RecoveryEpoch: current.Data.Run.RecoveryEpoch, Extensions: []generated.ContractExtension{}}
	response, err := requestTyped(client, ctx, profile, requestSpec{localtransport.MethodPost, "/api/v1/runs/" + runID + "/" + action, command, maxOperationResponseBodyBytes, operationTimeout, true}, input, validRunPresentation)
	if err == nil {
		return response, nil
	}
	inspected, inspectErr := client.InspectRun(context.WithoutCancel(ctx), profile, runID)
	if inspectErr == nil && inspected.ExitCode == 0 {
		return inspected, nil
	}
	return TypedResponse[generated.RunPresentation]{}, NewUncertainRunError(runID, err)
}

func (client *client) getPlan(ctx context.Context, profile serverconfig.Profile, planID string) (TypedResponse[generated.Plan], error) {
	if !validPathToken(planID) {
		return TypedResponse[generated.Plan]{}, failure.New(generated.ErrorCodeInputInvalid, "control-service-request", false)
	}
	presented, err := requestTyped(client, ctx, profile, requestSpec{localtransport.MethodGet, "/api/v1/plans/" + planID, "api.v1.plans.get", maxOperationResponseBodyBytes, operationTimeout, false}, nil, validPlanPresentation)
	if err != nil {
		return TypedResponse[generated.Plan]{}, err
	}
	return TypedResponse[generated.Plan]{Raw: presented.Raw, Result: presented.Result, Data: presented.Data.Plan, ExitCode: presented.ExitCode}, nil
}

func remapResponse[To, From any](response TypedResponse[From]) TypedResponse[To] {
	return TypedResponse[To]{Raw: response.Raw, Result: response.Result, ExitCode: response.ExitCode}
}

func requestTyped[T any](client *client, ctx context.Context, profile serverconfig.Profile, spec requestSpec, input any, validate func(T, generated.RunResult) bool) (TypedResponse[T], error) {
	var zero TypedResponse[T]
	remote := profile.ConstrainedSSH != nil
	if client == nil || client.results == nil || (profile.SocketPath == "") == !remote {
		return zero, responseFailure()
	}
	if !remote && runtime.GOOS == "windows" {
		return zero, failure.New(generated.ErrorCodeUnsupportedPlatform, "control-service", false)
	}
	var body []byte
	if spec.method == localtransport.MethodPost {
		raw, err := json.Marshal(input)
		if err != nil || len(raw) == 0 || len(raw) > maxOperationRequestBodyBytes {
			return zero, failure.New(generated.ErrorCodeInputInvalid, "control-service-request", false)
		}
		body = raw
	} else if input != nil {
		return zero, responseFailure()
	}
	request := localtransport.Request{SocketPath: profile.SocketPath, Method: spec.method, Path: spec.path, Body: body, Timeout: spec.timeout, ResponseLimit: spec.responseLimit}
	var response localtransport.Response
	var err error
	if remote {
		requestID, requestIDErr := client.results.RequestID()
		if requestIDErr != nil {
			return zero, requestIDErr
		}
		response, err = sshtransport.RoundTrip(ctx, sshtransport.Request{
			Executable: profile.ConstrainedSSH.Executable, Arguments: profile.ConstrainedSSH.Arguments,
			RequestID: requestID, SSHPrincipalID: profile.ConstrainedSSH.SSHPrincipalID, DeviceID: profile.ConstrainedSSH.DeviceID,
			RecoveryEpoch: profile.ConstrainedSSH.RecoveryEpoch, OperationArgs: remoteCommandArgumentsForInput(spec, input),
			Method: request.Method, Path: request.Path, Body: request.Body, Timeout: request.Timeout, ResponseLimit: request.ResponseLimit,
		})
	} else {
		response, err = localtransport.RoundTrip(ctx, request)
	}
	if err != nil {
		if errors.Is(err, localtransport.ErrInvalid) || errors.Is(err, localtransport.ErrRedirect) || errors.Is(err, sshtransport.ErrInvalid) {
			return zero, responseFailure()
		}
		if ctx.Err() != nil {
			return zero, failure.New(generated.ErrorCodeInterrupted, "control-service", false)
		}
		return zero, failure.New(generated.ErrorCodeDependencyUnavailable, "control-service", true)
	}
	mediaType, _, err := mime.ParseMediaType(response.ContentType)
	if err != nil || mediaType != "application/json" {
		return zero, responseFailure()
	}
	return validateTypedResponse(response.Body, response.StatusCode, spec, validate)
}

func remoteCommandArguments(spec requestSpec) []string {
	if spec.command == "api.v1.summary.get" {
		return []string{"--output", "json"}
	}
	if spec.command == "api.v1.plans.create" {
		if id, ok := pathID(spec.path, "/api/v1/declarations/", "/plans"); ok {
			return []string{"--change", id, "--output", "json"}
		}
		return nil
	}
	if spec.command == "api.v1.plans.execute" {
		if id, ok := pathID(spec.path, "/api/v1/plans/", "/execute"); ok {
			return []string{"--plan-id", id, "--output", "json"}
		}
		return nil
	}
	if spec.command == "api.v1.runs.get" {
		if id, ok := pathID(spec.path, "/api/v1/runs/", ""); ok {
			return []string{"--run-id", id, "--output", "json"}
		}
		return nil
	}
	arguments := map[string][]string{
		generated.CommandNameServerStatus:          {"server", "status"},
		"api.v1.summary.get":                       {"status"},
		"api.v1.database-status.get":               {"database", "status"},
		"api.v1.inventory-drafts.import":           {"inventory", "import"},
		"api.v1.inventory-diffs.create":            {"inventory", "diff"},
		"api.v1.inventory-exports.create":          {"inventory", "export"},
		"api.v1.declarations.plan-preparation.get": {"plan"},
		"api.v1.plans.create":                      {"plan"},
		"api.v1.plans.get":                         {"apply"},
		"api.v1.plans.execute":                     {"apply"},
		"api.v1.runs.get":                          {"run", "inspect"},
		"api.v1.runs.cancel":                       {"run", "cancel"},
		"api.v1.runs.resume":                       {"run", "resume"},
	}
	return append([]string(nil), arguments[spec.command]...)
}

func remoteCommandArgumentsForInput(spec requestSpec, input any) []string {
	if spec.command == "api.v1.credential-lifecycle-drafts.create" {
		if request, ok := input.(generated.CredentialLifecycleRequest); ok {
			switch request.Action {
			case "credential.stage":
				return []string{"credential", "stage"}
			case "credential.activate":
				return []string{"credential", "activate"}
			case "credential.rotate":
				return []string{"credential", "rotate"}
			case "credential.revoke":
				return []string{"credential", "revoke"}
			case "credential.recover":
				return []string{"credential", "recover"}
			}
		}
		return nil
	}
	return remoteCommandArguments(spec)
}

func pathID(path, prefix, suffix string) (string, bool) {
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		return "", false
	}
	id := strings.TrimSuffix(strings.TrimPrefix(path, prefix), suffix)
	return id, validPathToken(id)
}

func validateTypedResponse[T any](raw []byte, httpStatus int, spec requestSpec, validate func(T, generated.RunResult) bool) (TypedResponse[T], error) {
	var response TypedResponse[T]
	envelope, exitCode, err := validateEnvelope(raw, httpStatus, spec)
	if err != nil {
		return response, err
	}
	if len(envelope.Errors) == 0 || !bytes.Equal(envelope.Data, []byte("{}")) {
		decoder := json.NewDecoder(bytes.NewReader(envelope.Data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&response.Data); err != nil {
			return TypedResponse[T]{}, responseFailure()
		}
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF || !validate(response.Data, envelope) {
			return TypedResponse[T]{}, responseFailure()
		}
	}
	response.Raw = append([]byte(nil), raw...)
	response.Result = envelope
	response.ExitCode = exitCode
	return response, nil
}

func validateEnvelope(raw []byte, httpStatus int, spec requestSpec) (generated.RunResult, int, error) {
	if len(raw) < 2 || raw[len(raw)-1] != '\n' {
		return generated.RunResult{}, 0, responseFailure()
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var envelope generated.RunResult
	if err := decoder.Decode(&envelope); err != nil {
		return generated.RunResult{}, 0, responseFailure()
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return generated.RunResult{}, 0, responseFailure()
	}
	canonical, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(raw, append(canonical, '\n')) {
		return generated.RunResult{}, 0, responseFailure()
	}
	if envelope.Schema != generated.SchemaIDRunResult || schemaMajor(envelope.SchemaVersion) != generated.SchemaMajor || envelope.Command != spec.command ||
		envelope.RequestID == "" || envelope.ToolVersion == "" || envelope.ReleaseBuildID == "" || envelope.SnapshotDigest != nil || (!runEnvelopeCommand(spec.command) && (envelope.RunID != nil || envelope.PlanID != nil)) || (!spec.allowChanged && envelope.Changed) {
		return generated.RunResult{}, 0, responseFailure()
	}
	if len(envelope.Errors) == 0 {
		if envelope.Status != generated.RunStatusSucceeded || httpStatus != localtransport.StatusOK {
			return generated.RunResult{}, 0, responseFailure()
		}
		return envelope, 0, nil
	}
	if (!runEnvelopeCommand(spec.command) && envelope.Changed) || (envelope.Status != generated.RunStatusFailed && envelope.Status != generated.RunStatusInterrupted && envelope.Status != generated.RunStatusPartial && envelope.Status != generated.RunStatusCancelled) {
		return generated.RunResult{}, 0, responseFailure()
	}
	if spec.command != generated.CommandNameServerStatus && !runEnvelopeCommand(spec.command) && !bytes.Equal(envelope.Data, []byte("{}")) {
		return generated.RunResult{}, 0, responseFailure()
	}
	for _, resultError := range envelope.Errors {
		if resultError.Target == "" {
			return generated.RunResult{}, 0, responseFailure()
		}
		if _, ok := generated.ErrorExitCodes[resultError.Code]; !ok {
			return generated.RunResult{}, 0, responseFailure()
		}
	}
	first := envelope.Errors[0].Code
	interruptedStatus := envelope.Status == generated.RunStatusInterrupted || envelope.Status == generated.RunStatusCancelled
	if httpStatus != expectedHTTPStatus(first) || (first == generated.ErrorCodeInterrupted) != interruptedStatus {
		return generated.RunResult{}, 0, responseFailure()
	}
	return envelope, generated.ErrorExitCodes[first], nil
}

func runEnvelopeCommand(command string) bool {
	return command == "api.v1.plans.execute" || strings.HasPrefix(command, "api.v1.runs.")
}

func expectedHTTPStatus(code string) int {
	return map[string]int{
		generated.ErrorCodeAuthenticationRequired: localtransport.StatusUnauthorized,
		generated.ErrorCodeAuthorizationDenied:    localtransport.StatusForbidden,
		generated.ErrorCodeInputInvalid:           localtransport.StatusBadRequest,
		generated.ErrorCodeSchemaUnsupported:      localtransport.StatusBadRequest,
		generated.ErrorCodeStateConflict:          localtransport.StatusConflict,
		generated.ErrorCodeRecoveryEpochMismatch:  localtransport.StatusConflict,
		generated.ErrorCodeResourceNotFound:       localtransport.StatusNotFound,
		generated.ErrorCodePrerequisiteBlocked:    localtransport.StatusPreconditionFailed,
		generated.ErrorCodeInterrupted:            localtransport.StatusRequestTimeout,
		generated.ErrorCodeDependencyUnavailable:  localtransport.StatusServiceUnavailable,
		generated.ErrorCodeIntegrityFailure:       localtransport.StatusServiceUnavailable,
		generated.ErrorCodeApprovalRequired:       localtransport.StatusPreconditionFailed,
		generated.ErrorCodePlanStale:              localtransport.StatusConflict,
		generated.ErrorCodeExecutionFailed:        localtransport.StatusBadGateway,
		generated.ErrorCodeExecutionPartial:       localtransport.StatusConflict,
		generated.ErrorCodeRecoveryRequired:       localtransport.StatusConflict,
	}[code]
}

func validRemoteStatus(status generated.ServerStatusData, envelope generated.RunResult) bool {
	if status.RecoveryEpoch != envelope.RecoveryEpoch || status.StateRevision != envelope.StateRevision || status.MutationAvailable || status.State == "unavailable" {
		return false
	}
	switch status.State {
	case "ready", "safe-mode":
		return status.ReadAvailable
	case "starting", "stopping":
		return !status.ReadAvailable
	default:
		return false
	}
}

func validSummary(value generated.ApiSummaryData, envelope generated.RunResult) bool {
	counts := value.SourceCounts
	counted := counts.Healthy + counts.Stale + counts.Unknown + counts.Unavailable + counts.Failed
	return value.StateRevision == envelope.StateRevision && value.RecoveryEpoch == envelope.RecoveryEpoch && value.DatabaseMode != "" &&
		counts.Total == 7 && counted == counts.Total && counts.Healthy >= 0 && counts.Stale >= 0 && counts.Unknown >= 0 && counts.Unavailable >= 0 && counts.Failed >= 0 &&
		value.WorstSourceState == worstSourceState(counts)
}

func worstSourceState(counts generated.ApiSourceCountsData) string {
	switch {
	case counts.Failed > 0:
		return "failed"
	case counts.Stale > 0:
		return "stale"
	case counts.Unknown > 0:
		return "unknown"
	case counts.Unavailable > 0:
		return "unavailable"
	default:
		return "healthy"
	}
}

func validDatabaseStatus(value generated.DatabaseStatusData, _ generated.RunResult) bool {
	return value.Mode != "" && value.SchemaVersion > 0 && value.SQLiteVersion != "" && value.IntegrityStatus != ""
}

func validImportData(value generated.InventoryImportData, envelope generated.RunResult) bool {
	return value.DraftID != "" && value.DraftRevision > 0 && value.StateRevision == envelope.StateRevision && value.RecoveryEpoch == envelope.RecoveryEpoch && value.Created == envelope.Changed
}

func validDiffData(value generated.InventoryDiffData, envelope generated.RunResult) bool {
	return (value.CandidateKind == "draft" || value.CandidateKind == "file") && value.BaselineKind == "draft" && value.BaselineDraft.DraftID != "" && value.BaselineDraft.DraftRevision > 0 && value.StateRevision == envelope.StateRevision && value.RecoveryEpoch == envelope.RecoveryEpoch
}

func validExportData(value generated.InventoryExportData, envelope generated.RunResult) bool {
	return value.ExportID != "" && value.SubjectKind == "draft" && value.Draft.DraftID != "" && value.Draft.DraftRevision > 0 && value.StateRevision == envelope.StateRevision && value.RecoveryEpoch == envelope.RecoveryEpoch
}

func validPlanPreparation(value generated.PlanPreparation, envelope generated.RunResult) bool {
	raw, err := json.Marshal(value)
	return err == nil && generated.ValidateContractJSON(generated.SchemaIDPlanPreparation, raw, generated.ContractExact) == nil && validPathToken(value.DeclarationID) && value.DeclarationRevision > 0 && value.ExpectedStateRevision == envelope.StateRevision && value.RecoveryEpoch == envelope.RecoveryEpoch
}

func validPlan(value generated.Plan, envelope generated.RunResult) bool {
	raw, err := json.Marshal(value)
	return err == nil && generated.ValidateContractJSON(generated.SchemaIDPlan, raw, generated.ContractExact) == nil && value.PlanID != "" && value.PlanDigest != "" && value.Binding.RecoveryEpoch == envelope.RecoveryEpoch && value.Binding.StateRevision == envelope.StateRevision
}

func validPlanPresentation(value generated.PlanPresentation, envelope generated.RunResult) bool {
	raw, err := json.Marshal(value)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDPlanPresentation, raw, generated.ContractExact) != nil || !validPlan(value.Plan, envelope) || value.ReadablePlan == "" || value.CanonicalPlan == "" {
		return false
	}
	planRaw, err := json.Marshal(value.Plan)
	return err == nil && string(planRaw) == value.CanonicalPlan
}

func validRun(value generated.Run, envelope generated.RunResult) bool {
	raw, err := json.Marshal(value)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDRun, raw, generated.ContractExact) != nil || value.RunID == "" || value.PlanID == "" || value.RecoveryEpoch != envelope.RecoveryEpoch || value.StateRevision != envelope.StateRevision {
		return false
	}
	return (envelope.RunID == nil || *envelope.RunID == value.RunID) && (envelope.PlanID == nil || *envelope.PlanID == value.PlanID)
}

func validBrowserRun(value generated.BrowserRun, envelope generated.RunResult) bool {
	raw, err := json.Marshal(value)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDBrowserRun, raw, generated.ContractExact) != nil || value.RunID == "" || value.PlanID == "" || value.RecoveryEpoch != envelope.RecoveryEpoch || value.StateRevision != envelope.StateRevision {
		return false
	}
	return (envelope.RunID == nil || *envelope.RunID == value.RunID) && (envelope.PlanID == nil || *envelope.PlanID == value.PlanID)
}

func validRunPresentation(value generated.RunPresentation, envelope generated.RunResult) bool {
	raw, err := json.Marshal(value)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDRunPresentation, raw, generated.ContractExact) != nil || !validBrowserRun(value.Run, envelope) || value.NextSafeAction == "" {
		return false
	}
	want := make(map[string]generated.BrowserRunStep, len(value.Run.Steps))
	for _, step := range value.Run.Steps {
		if step.StepID == "" {
			return false
		}
		want[step.StepID] = step
	}
	seen := make(map[string]struct{}, len(want))
	for _, group := range [][]generated.BrowserRunStep{value.CompletedWork, value.IncompleteWork} {
		for _, step := range group {
			original, ok := want[step.StepID]
			if !ok || original != step {
				return false
			}
			if _, duplicate := seen[step.StepID]; duplicate {
				return false
			}
			seen[step.StepID] = struct{}{}
		}
	}
	return len(seen) == len(want)
}

func validPathToken(value string) bool {
	if len(value) < 1 || len(value) > 128 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '.' && character != '-' && character != '_' && character != ':' {
			return false
		}
	}
	return true
}

func schemaMajor(version string) int {
	major, _, ok := strings.Cut(version, ".")
	if !ok {
		return 0
	}
	value, err := strconv.Atoi(major)
	if err != nil {
		return 0
	}
	return value
}

func responseFailure() error {
	return failure.New(generated.ErrorCodeIntegrityFailure, "control-service-response", false)
}
