package localapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

const (
	maxResponseBodyBytes          = 64 * 1024
	maxOperationResponseBodyBytes = 24 << 20
	maxOperationRequestBodyBytes  = 8 << 20
	maxResponseHeaders            = 16 * 1024
	statusTimeout                 = 3 * time.Second
	operationTimeout              = 30 * time.Second
)

var errRedirect = errors.New("redirect denied")

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
	Status(context.Context, serverconfig.Profile) (Response, error)
	Summary(context.Context, serverconfig.Profile) (TypedResponse[generated.ApiSummaryData], error)
	DatabaseStatus(context.Context, serverconfig.Profile) (TypedResponse[generated.DatabaseStatusData], error)
	ImportInventory(context.Context, serverconfig.Profile, generated.InventoryImportRequest) (TypedResponse[generated.InventoryImportData], error)
	DiffInventory(context.Context, serverconfig.Profile, generated.InventoryDiffRequest) (TypedResponse[generated.InventoryDiffData], error)
	ExportInventory(context.Context, serverconfig.Profile, generated.InventoryExportRequest) (TypedResponse[generated.InventoryExportData], error)
}

type client struct{ results *result.Factory }

type requestSpec struct {
	method, path, command string
	responseLimit         int64
	timeout               time.Duration
	allowChanged          bool
}

func NewClient(results *result.Factory) Client { return &client{results: results} }

func (client *client) Status(ctx context.Context, profile serverconfig.Profile) (Response, error) {
	typed, err := requestTyped(client, ctx, profile, requestSpec{http.MethodGet, "/api/v1/health", generated.CommandNameServerStatus, maxResponseBodyBytes, statusTimeout, false}, nil, validRemoteStatus)
	if err != nil {
		return Response{}, err
	}
	return Response{Raw: typed.Raw, Result: typed.Result, Status: typed.Data, ExitCode: typed.ExitCode}, nil
}

func (client *client) Summary(ctx context.Context, profile serverconfig.Profile) (TypedResponse[generated.ApiSummaryData], error) {
	return requestTyped(client, ctx, profile, requestSpec{http.MethodGet, "/api/v1/summary", generated.CommandNameStatus, maxResponseBodyBytes, statusTimeout, false}, nil, validSummary)
}

func (client *client) DatabaseStatus(ctx context.Context, profile serverconfig.Profile) (TypedResponse[generated.DatabaseStatusData], error) {
	return requestTyped(client, ctx, profile, requestSpec{http.MethodGet, "/api/v1/database/status", generated.CommandNameDatabaseStatus, maxResponseBodyBytes, statusTimeout, false}, nil, validDatabaseStatus)
}

func (client *client) ImportInventory(ctx context.Context, profile serverconfig.Profile, input generated.InventoryImportRequest) (TypedResponse[generated.InventoryImportData], error) {
	return requestTyped(client, ctx, profile, requestSpec{http.MethodPost, "/api/v1/inventory-drafts/import", generated.CommandNameInventoryImport, maxOperationResponseBodyBytes, operationTimeout, true}, input, validImportData)
}

func (client *client) DiffInventory(ctx context.Context, profile serverconfig.Profile, input generated.InventoryDiffRequest) (TypedResponse[generated.InventoryDiffData], error) {
	return requestTyped(client, ctx, profile, requestSpec{http.MethodPost, "/api/v1/inventory-diffs", generated.CommandNameInventoryDiff, maxOperationResponseBodyBytes, operationTimeout, false}, input, validDiffData)
}

func (client *client) ExportInventory(ctx context.Context, profile serverconfig.Profile, input generated.InventoryExportRequest) (TypedResponse[generated.InventoryExportData], error) {
	return requestTyped(client, ctx, profile, requestSpec{http.MethodPost, "/api/v1/inventory-exports", generated.CommandNameInventoryExport, maxOperationResponseBodyBytes, operationTimeout, true}, input, validExportData)
}

func requestTyped[T any](client *client, ctx context.Context, profile serverconfig.Profile, spec requestSpec, input any, validate func(T, generated.RunResult) bool) (TypedResponse[T], error) {
	var zero TypedResponse[T]
	if client == nil || client.results == nil || profile.SocketPath == "" {
		return zero, responseFailure()
	}
	if runtime.GOOS == "windows" {
		return zero, failure.New(generated.ErrorCodeUnsupportedPlatform, "control-service", false)
	}
	var body io.Reader
	if spec.method == http.MethodPost {
		raw, err := json.Marshal(input)
		if err != nil || len(raw) == 0 || len(raw) > maxOperationRequestBodyBytes {
			return zero, failure.New(generated.ErrorCodeInputInvalid, "control-service-request", false)
		}
		body = bytes.NewReader(raw)
	} else if input != nil {
		return zero, responseFailure()
	}
	requestCtx, cancel := context.WithTimeout(ctx, spec.timeout)
	defer cancel()
	dialer := &net.Dialer{}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", profile.SocketPath)
		},
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: maxResponseHeaders,
	}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, Timeout: spec.timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return errRedirect }}
	request, err := http.NewRequestWithContext(requestCtx, spec.method, "http://local"+spec.path, body)
	if err != nil {
		return zero, responseFailure()
	}
	if spec.method == http.MethodPost {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := httpClient.Do(request)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		if errors.Is(err, errRedirect) {
			return zero, responseFailure()
		}
		if ctx.Err() != nil {
			return zero, failure.New(generated.ErrorCodeInterrupted, "control-service", false)
		}
		var networkError *net.OpError
		if errors.As(err, &networkError) && (networkError.Op == "dial" || networkError.Timeout()) {
			return zero, failure.New(generated.ErrorCodeDependencyUnavailable, "control-service", true)
		}
		return zero, responseFailure()
	}
	defer response.Body.Close()
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return zero, responseFailure()
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, spec.responseLimit+1))
	if err != nil || len(raw) == 0 || int64(len(raw)) > spec.responseLimit {
		return zero, responseFailure()
	}
	return validateTypedResponse(raw, response.StatusCode, spec, validate)
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
		envelope.RequestID == "" || envelope.ToolVersion == "" || envelope.ReleaseBuildID == "" || envelope.RunID != nil || envelope.SnapshotDigest != nil || envelope.PlanID != nil || (!spec.allowChanged && envelope.Changed) {
		return generated.RunResult{}, 0, responseFailure()
	}
	if len(envelope.Errors) == 0 {
		if envelope.Status != generated.RunStatusSucceeded || httpStatus != http.StatusOK {
			return generated.RunResult{}, 0, responseFailure()
		}
		return envelope, 0, nil
	}
	if envelope.Changed || (envelope.Status != generated.RunStatusFailed && envelope.Status != generated.RunStatusInterrupted) {
		return generated.RunResult{}, 0, responseFailure()
	}
	if spec.command != generated.CommandNameServerStatus && !bytes.Equal(envelope.Data, []byte("{}")) {
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
	if httpStatus != expectedHTTPStatus(first) || (first == generated.ErrorCodeInterrupted) != (envelope.Status == generated.RunStatusInterrupted) {
		return generated.RunResult{}, 0, responseFailure()
	}
	return envelope, generated.ErrorExitCodes[first], nil
}

func expectedHTTPStatus(code string) int {
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
	return value.StateRevision == envelope.StateRevision && value.RecoveryEpoch == envelope.RecoveryEpoch && value.DatabaseMode != ""
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
