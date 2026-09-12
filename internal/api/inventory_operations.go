package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/inventory"
	"github.com/vegastack/vegastack-labs/internal/inventoryops"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/stateexport"
	"github.com/vegastack/vegastack-labs/internal/strictjson"
)

const MaxOperationRequestBytes = 8 << 20

type ExportService interface {
	Export(context.Context, stateexport.Request) (stateexport.Result, error)
}

type InventoryOperationConfig struct {
	Decoders     inventoryops.DecoderRegistry
	Imports      inventory.ImportService
	Diffs        *inventoryops.DiffService
	Exports      ExportService
	Results      *result.Factory
	MaxBodyBytes int64
}

func RegisterInventoryOperations(app *Application, config InventoryOperationConfig) error {
	if app == nil || config.Decoders == nil || config.Imports == nil || config.Diffs == nil || config.Exports == nil || config.Results == nil || config.Results != app.config.Results {
		return apiFailure(generated.ErrorCodeInputInvalid, "inventory-operation-config")
	}
	if config.MaxBodyBytes == 0 {
		config.MaxBodyBytes = MaxOperationRequestBytes
	}
	if config.MaxBodyBytes < 1 || config.MaxBodyBytes > MaxOperationRequestBytes {
		return apiFailure(generated.ErrorCodeInputInvalid, "inventory-operation-limit")
	}
	app.routes = append(app.routes,
		route{id: "api.v1.inventory-drafts.import", method: http.MethodPost, pattern: "/api/v1/inventory-drafts/import", capability: "inventory.draft.create", kind: "inventory-drafts", handler: app.importDraft(config)},
		route{id: "api.v1.inventory-diffs.create", method: http.MethodPost, pattern: "/api/v1/inventory-diffs", capability: "inventory.draft.diff", kind: "inventory-draft", handler: app.diffDraft(config)},
		route{id: "api.v1.inventory-exports.create", method: http.MethodPost, pattern: "/api/v1/inventory-exports", capability: "inventory.draft.export", kind: "inventory-draft", handler: app.exportDraft(config)},
	)
	if !routesAreGeneratedSubset(app.routes) {
		app.routes = app.routes[:len(app.routes)-3]
		return apiFailure(generated.ErrorCodeIntegrityFailure, "endpoint-registry")
	}
	return nil
}

func (app *Application) importDraft(config InventoryOperationConfig) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(writer http.ResponseWriter, request *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const operation = "api.v1.inventory-drafts.import"
		var input generated.InventoryImportRequest
		if err := decodeOperationRequest(request, config.MaxBodyBytes, []string{"format", "sourceRevision", "capturedAt", "idempotencyKey", "expectedStateRevision", "content"}, &input); err != nil {
			app.failure(writer, operation, err)
			return
		}
		captured, err := parseUTCTime(input.CapturedAt)
		if err != nil || input.Format == "" || input.SourceRevision == "" || input.IdempotencyKey == "" || len(input.Content) == 0 || (input.ExpectedStateRevision != nil && *input.ExpectedStateRevision < 0) {
			app.failure(writer, operation, apiFailure(generated.ErrorCodeInputInvalid, "inventory-import-request"))
			return
		}
		decoded, err := config.Decoders.Decode(request.Context(), inventoryops.DecoderRequest{Format: input.Format, SourceRevision: input.SourceRevision, CapturedAt: captured, Content: []byte(input.Content)})
		if err != nil {
			app.failure(writer, operation, err)
			return
		}
		requestID, err := config.Results.RequestID()
		if err != nil {
			app.failure(writer, operation, err)
			return
		}
		value, err := config.Imports.ValidateAndStore(request.Context(), inventory.ImportRequest{IdempotencyKey: input.IdempotencyKey, CorrelationID: requestID, ExpectedStateRevision: input.ExpectedStateRevision, Decoded: decoded})
		if err != nil {
			app.operationFailure(writer, operation, requestID, err)
			return
		}
		data := generated.InventoryImportData{DraftID: string(value.DraftID), DraftRevision: value.DraftRevision, ValidationStatus: string(value.ValidationStatus), SourceDigest: value.SourceDigest, ContentDigest: value.ContentDigest, StateRevision: value.StateRevision, RecoveryEpoch: value.RecoveryEpoch, EventID: int64(value.EventID), Created: value.Created, Counts: counts(value.Counts), Findings: projectFindings(value.Findings)}
		app.operationSuccess(writer, operation, requestID, value.Created, value.StateRevision, value.RecoveryEpoch, data)
	}
}

func (app *Application) diffDraft(config InventoryOperationConfig) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(writer http.ResponseWriter, request *http.Request, scope authorization.ReadScope, _ map[string]string) {
		const operation = "api.v1.inventory-diffs.create"
		var input generated.InventoryDiffRequest
		if err := decodeOperationRequest(request, config.MaxBodyBytes, []string{"candidateKind", "draft", "format", "sourceRevision", "capturedAt", "content"}, &input); err != nil {
			app.failure(writer, operation, err)
			return
		}
		candidate := inventoryops.Candidate{Kind: input.CandidateKind}
		switch input.CandidateKind {
		case "draft":
			if input.Draft == nil || input.Format != nil || input.SourceRevision != nil || input.CapturedAt != nil || input.Content != nil || input.Draft.DraftID == "" || input.Draft.DraftRevision < 1 {
				app.failure(writer, operation, apiFailure(generated.ErrorCodeInputInvalid, "inventory-diff-request"))
				return
			}
			ref := inventory.DraftRef{ID: inventory.DraftID(input.Draft.DraftID), Revision: input.Draft.DraftRevision}
			candidate.Draft = &ref
		case "file":
			if input.Draft != nil || input.Format == nil || input.SourceRevision == nil || input.CapturedAt == nil || input.Content == nil || *input.Format == "" || *input.SourceRevision == "" || *input.Content == "" {
				app.failure(writer, operation, apiFailure(generated.ErrorCodeInputInvalid, "inventory-diff-request"))
				return
			}
			captured, err := parseUTCTime(*input.CapturedAt)
			if err != nil {
				app.failure(writer, operation, apiFailure(generated.ErrorCodeInputInvalid, "inventory-diff-request"))
				return
			}
			candidate.File = &inventoryops.DecoderRequest{Format: *input.Format, SourceRevision: *input.SourceRevision, CapturedAt: captured, Content: []byte(*input.Content)}
		default:
			app.failure(writer, operation, apiFailure(generated.ErrorCodeInputInvalid, "inventory-diff-request"))
			return
		}
		requestID, err := config.Results.RequestID()
		if err != nil {
			app.failure(writer, operation, err)
			return
		}
		value, err := config.Diffs.Diff(request.Context(), inventoryops.DiffRequest{Scope: scope, Candidate: candidate})
		if err != nil {
			app.operationFailure(writer, operation, requestID, err)
			return
		}
		var candidateDraft *generated.InventoryDraftRef
		if value.CandidateDraft != nil {
			candidateDraft = projectDraftRef(*value.CandidateDraft)
		}
		data := generated.InventoryDiffData{CandidateKind: value.CandidateKind, CandidateDraft: candidateDraft, CandidateDigest: value.CandidateDigest, BaselineKind: value.BaselineKind, BaselineDraft: *projectDraftRef(value.BaselineDraft), StateRevision: value.StateRevision, RecoveryEpoch: value.RecoveryEpoch, Counts: value.Counts, Records: value.Records, Findings: projectFindings(value.Findings)}
		app.operationSuccess(writer, operation, requestID, false, value.StateRevision, value.RecoveryEpoch, data)
	}
}

func (app *Application) exportDraft(config InventoryOperationConfig) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(writer http.ResponseWriter, request *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const operation = "api.v1.inventory-exports.create"
		var input generated.InventoryExportRequest
		if err := decodeOperationRequest(request, config.MaxBodyBytes, []string{"draft"}, &input); err != nil {
			app.failure(writer, operation, err)
			return
		}
		ref := inventory.DraftRef{ID: inventory.DraftID(input.Draft.DraftID), Revision: input.Draft.DraftRevision}
		if authorization.ResourceID(ref) == "" {
			app.failure(writer, operation, apiFailure(generated.ErrorCodeInputInvalid, "inventory-export-request"))
			return
		}
		principal, ok := identity.PrincipalFromContext(request.Context())
		if !ok {
			app.failure(writer, operation, apiFailure(generated.ErrorCodeAuthenticationRequired, "principal"))
			return
		}
		if _, err := app.config.Authorizer.AuthorizeRead(request.Context(), principal, authorization.ReadTarget{Capability: "inventory.draft.export", ResourceKind: "inventory-draft", ResourceID: authorization.ResourceID(ref)}); err != nil {
			app.failure(writer, operation, err)
			return
		}
		requestID, err := config.Results.RequestID()
		if err != nil {
			app.failure(writer, operation, err)
			return
		}
		value, err := config.Exports.Export(request.Context(), stateexport.Request{CorrelationID: requestID, IdempotencyKey: requestID, Draft: ref})
		if err != nil {
			app.operationFailure(writer, operation, requestID, err)
			return
		}
		data := generated.InventoryExportData{ExportID: value.ExportID, SubjectKind: value.SubjectKind, Draft: *projectDraftRef(value.Draft), StateRevision: value.StateRevision, RecoveryEpoch: value.RecoveryEpoch, ContentDigest: value.ContentDigest, Algorithm: value.Algorithm, KeyID: value.KeyID, KeyFingerprint: value.KeyFingerprint, VerificationStatus: value.VerificationStatus, PublicationStatus: value.PublicationStatus, SignedBytesBase64: base64.StdEncoding.EncodeToString(value.CanonicalBytes)}
		app.operationSuccess(writer, operation, requestID, value.Created, value.StateRevision, value.RecoveryEpoch, data)
	}
}

func decodeOperationRequest(request *http.Request, limit int64, required []string, target any) error {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || request.Body == nil || request.ContentLength == 0 || request.ContentLength > limit || request.URL.RawQuery != "" {
		return apiFailure(generated.ErrorCodeInputInvalid, "request-body")
	}
	raw, err := io.ReadAll(io.LimitReader(request.Body, limit+1))
	if request.Context().Err() != nil {
		return failure.New(generated.ErrorCodeInterrupted, "request-body", false)
	}
	if err != nil || int64(len(raw)) > limit || len(raw) == 0 || !utf8.Valid(raw) {
		return apiFailure(generated.ErrorCodeInputInvalid, "request-body")
	}
	if err := strictjson.Scan(request.Context(), raw, strictjson.Limits{MaxDepth: 32}); err != nil {
		return apiFailure(generated.ErrorCodeInputInvalid, "request-body")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != len(required) {
		return apiFailure(generated.ErrorCodeInputInvalid, "request-body")
	}
	for _, field := range required {
		if _, ok := fields[field]; !ok {
			return apiFailure(generated.ErrorCodeInputInvalid, "request-body")
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return apiFailure(generated.ErrorCodeInputInvalid, "request-body")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return apiFailure(generated.ErrorCodeInputInvalid, "request-body")
	}
	return nil
}

func parseUTCTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, err
	}
	_, offset := parsed.Zone()
	if offset != 0 {
		return time.Time{}, errors.New("not UTC")
	}
	return parsed.UTC(), nil
}

func projectDraftRef(ref inventory.DraftRef) *generated.InventoryDraftRef {
	return &generated.InventoryDraftRef{DraftID: string(ref.ID), DraftRevision: ref.Revision}
}
func projectFindings(values []inventory.Finding) []generated.InventoryFinding {
	result := make([]generated.InventoryFinding, 0, len(values))
	for _, value := range values {
		related := make([]string, len(value.RelatedIDs))
		for index := range value.RelatedIDs {
			related[index] = string(value.RelatedIDs[index])
		}
		result = append(result, generated.InventoryFinding{Code: value.Code, Severity: value.Severity, Blocking: value.Blocking, RecordKind: value.RecordKind, RecordID: string(value.RecordID), FieldPath: value.FieldPath, Location: value.Location, RelatedIDs: related})
	}
	return result
}

func classifyOperationError(err error) (string, string, bool) {
	code, retryable := generated.ErrorCodeDependencyUnavailable, false
	if stable, ok := failure.As(err); ok {
		code, retryable = stable.Code, stable.Retryable
	} else if coded, ok := err.(interface{ Code() string }); ok {
		code = coded.Code()
	} else if typed, ok := err.(*inventory.Error); ok {
		code = typed.Code
	}
	if _, ok := generated.ErrorExitCodes[code]; !ok {
		code = generated.ErrorCodeDependencyUnavailable
	}
	return code, "inventory-operation", retryable
}

var _ ExportService = (*stateexport.Service)(nil)
