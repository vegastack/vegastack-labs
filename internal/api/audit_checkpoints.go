package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type AuditRepository interface {
	ListAuditCheckpoints(context.Context) ([]generated.AuditCheckpoint, error)
	ListAuditCheckpointsPageScoped(context.Context, authorization.ReadScope, store.RevisionToken, string, int) ([]generated.AuditCheckpoint, error)
	VerifyAuditHistory(context.Context, adapter.CheckpointReader) (generated.AuditVerificationData, error)
	ChainRange(context.Context, audit.EventID, audit.EventID) (audit.ChainRange, error)
}

type AuditOperations struct {
	Audit        AuditRepository
	Independent  adapter.CheckpointReader
	Revisions    AuditRevisionRepository
	Declarations DeclarationService
	Results      *result.Factory
}

type AuditRevisionRepository interface {
	CurrentRevision(context.Context) (store.RevisionToken, error)
}

func RegisterAuditOperations(app *Application, config AuditOperations) error {
	if app == nil || config.Audit == nil || config.Revisions == nil || config.Declarations == nil || config.Results == nil || config.Results != app.config.Results {
		return apiFailure(generated.ErrorCodeInputInvalid, "audit-config")
	}
	app.routes = append(app.routes,
		route{id: "api.v1.audit-checkpoints.list", method: http.MethodGet, pattern: "/api/v1/audit-checkpoints", capability: "audit.checkpoint.read", kind: "audit-checkpoint", handler: app.auditCheckpoints(config)},
		route{id: "api.v1.audit-checkpoints.create", method: http.MethodPost, pattern: "/api/v1/audit-checkpoints", capability: "audit.checkpoint.author", kind: "audit-checkpoint", action: authorization.ActionAuthor, staticResourceID: "audit-checkpoints", handler: app.auditCheckpointDraft(config)},
		route{id: "api.v1.audit-history.verification", method: http.MethodGet, pattern: "/api/v1/audit-history/verification", capability: "audit.history.verify", kind: "audit-history", handler: app.auditVerification(config)},
	)
	if !routesAreGeneratedSubset(app.routes) {
		app.routes = app.routes[:len(app.routes)-3]
		return apiFailure(generated.ErrorCodeIntegrityFailure, "endpoint-registry")
	}
	return nil
}

func (app *Application) auditCheckpoints(config AuditOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(writer http.ResponseWriter, request *http.Request, scope authorization.ReadScope, _ map[string]string) {
		const operation = "api.v1.audit-checkpoints.list"
		page, err := app.phase5PageRequest(request, scope, operation)
		if err != nil {
			app.failure(writer, operation, err)
			return
		}
		checkpoints, err := config.Audit.ListAuditCheckpointsPageScoped(request.Context(), scope, page.Snapshot, page.AfterID, page.Query.Limit+1)
		if err != nil {
			app.failure(writer, operation, err)
			return
		}
		revision, err := config.Revisions.CurrentRevision(request.Context())
		if err != nil {
			app.failure(writer, operation, err)
			return
		}
		if revision != page.Snapshot {
			app.failure(writer, operation, apiFailure(generated.ErrorCodeStateConflict, "cursor"))
			return
		}
		hasMore := len(checkpoints) > page.Query.Limit
		if hasMore {
			checkpoints = checkpoints[:page.Query.Limit]
		}
		items := make([]generated.BrowserAuditCheckpoint, 0, len(checkpoints))
		for _, checkpoint := range checkpoints {
			items = append(items, generated.BrowserAuditCheckpoint{Schema: generated.SchemaIDBrowserAuditCheckpoint, SchemaVersion: "1.0.0", CheckpointID: checkpoint.CheckpointID, FirstEventID: checkpoint.FirstEventID, LastEventID: checkpoint.LastEventID, ChainDigest: checkpoint.ChainDigest, Status: checkpoint.Status, ReasonCode: checkpoint.ReasonCode, SourceKind: checkpoint.SourceKind, ProofClass: checkpoint.ProofClass, VerifiedAt: checkpoint.VerifiedAt, VerificationStatus: checkpoint.VerificationStatus, RecoveryEpoch: checkpoint.RecoveryEpoch})
		}
		var lastID string
		if len(items) > 0 {
			lastID = items[len(items)-1].CheckpointID
		}
		next, err := app.phase5NextCursor(operation, scope, page, lastID, hasMore)
		if err != nil {
			app.failure(writer, operation, err)
			return
		}
		data := generated.BrowserAuditCheckpointListData{Schema: generated.SchemaIDBrowserAuditCheckpointListData, SchemaVersion: "1.0.0", Items: items, NextCursor: next, StateRevision: revision.StateRevision, RecoveryEpoch: revision.RecoveryEpoch}
		raw, err := json.Marshal(data)
		if err != nil || generated.ValidateContractJSON(generated.SchemaIDBrowserAuditCheckpointListData, raw, generated.ContractExact) != nil {
			app.failure(writer, operation, apiFailure(generated.ErrorCodeIntegrityFailure, "audit-checkpoint-projection"))
			return
		}
		app.success(writer, operation, revision.StateRevision, revision.RecoveryEpoch, data)
	}
}

func (app *Application) auditVerification(config AuditOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(writer http.ResponseWriter, request *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const operation = "api.v1.audit-history.verification"
		data, err := config.Audit.VerifyAuditHistory(request.Context(), config.Independent)
		if err != nil && data.Status != "incident" {
			app.failure(writer, operation, err)
			return
		}
		revision, revisionErr := config.Revisions.CurrentRevision(request.Context())
		if revisionErr != nil {
			app.failure(writer, operation, revisionErr)
			return
		}
		sourceKind, proofClass := "none", "none"
		if data.IndependentDigest != nil {
			sourceKind, proofClass = "independent", "live"
		}
		status, next, ok := browserAuditVerificationStatus(data.Status)
		if !ok {
			app.failure(writer, operation, apiFailure(generated.ErrorCodeIntegrityFailure, "audit-verification-status"))
			return
		}
		projected := generated.BrowserAuditVerificationData{Schema: generated.SchemaIDBrowserAuditVerificationData, SchemaVersion: "1.0.0", Status: status, ReasonCode: data.ReasonCode, SourceKind: sourceKind, ProofClass: proofClass, IndependentMatch: data.IndependentMatch, LastAnchoredSequence: data.LastAnchoredSequence, PreAnchor: data.PreAnchor, StateRevision: revision.StateRevision, RecoveryEpoch: revision.RecoveryEpoch, SafeNextAction: next}
		raw, marshalErr := json.Marshal(projected)
		if marshalErr != nil || generated.ValidateContractJSON(generated.SchemaIDBrowserAuditVerificationData, raw, generated.ContractExact) != nil {
			app.failure(writer, operation, apiFailure(generated.ErrorCodeIntegrityFailure, "audit-verification-projection"))
			return
		}
		app.success(writer, operation, revision.StateRevision, revision.RecoveryEpoch, projected)
	}
}

func browserAuditVerificationStatus(status string) (string, string, bool) {
	switch status {
	case "pending":
		return "pending", "collect an independent audit checkpoint", true
	case "anchored", "healthy":
		return "anchored", "none", true
	case "degraded":
		return "degraded", "collect and compare an independent audit checkpoint", true
	case "incident":
		return "incident", "investigate the audit integrity incident", true
	default:
		return "", "", false
	}
}

func (app *Application) auditCheckpointDraft(config AuditOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(writer http.ResponseWriter, request *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const operation = "api.v1.audit-checkpoints.create"
		var input generated.AuditCheckpointRequest
		if err := decodeOperationRequest(request, MaxOperationRequestBytes, []string{"schema", "schemaVersion", "expectedStateRevision", "recoveryEpoch", "targetDigest", "idempotencyKey", "firstEventId", "lastEventId"}, &input); err != nil {
			app.failure(writer, operation, err)
			return
		}
		raw, err := json.Marshal(input)
		if err != nil || generated.ValidateContractJSON(generated.SchemaIDAuditCheckpointRequest, raw, generated.ContractExact) != nil {
			app.failure(writer, operation, apiFailure(generated.ErrorCodeInputInvalid, "audit-checkpoint-request"))
			return
		}
		requestID, err := config.Results.RequestID()
		if err != nil {
			app.failure(writer, operation, err)
			return
		}
		revision, err := config.Revisions.CurrentRevision(request.Context())
		if err != nil || revision != (store.RevisionToken{StateRevision: input.ExpectedStateRevision, RecoveryEpoch: input.RecoveryEpoch}) {
			app.operationFailure(writer, operation, requestID, apiFailure(generated.ErrorCodeStateConflict, "audit-checkpoint-revision"))
			return
		}
		chain, err := config.Audit.ChainRange(request.Context(), audit.EventID(input.FirstEventID), audit.EventID(input.LastEventID))
		if err != nil || string(chain.RangeDigest) != input.TargetDigest {
			app.operationFailure(writer, operation, requestID, apiFailure(generated.ErrorCodeStateConflict, "audit-checkpoint-range"))
			return
		}
		declaration, err := change.BuildCheckpointChange(chain, revision)
		if err != nil {
			app.operationFailure(writer, operation, requestID, err)
			return
		}
		principal, ok := identity.PrincipalFromContext(request.Context())
		if !ok {
			app.failure(writer, operation, apiFailure(generated.ErrorCodeAuthenticationRequired, "principal"))
			return
		}
		value, err := config.Declarations.Revise(request.Context(), change.AuthorScope{PrincipalID: principal.ID, PrincipalMethod: principal.Method, AgentSessionID: requestID}, declaration)
		if err != nil {
			app.operationFailure(writer, operation, requestID, err)
			return
		}
		checkpoint := generated.AuditCheckpoint{
			Schema: generated.SchemaIDAuditCheckpoint, SchemaVersion: "1.1.0", CheckpointID: value.Document.DeclarationID,
			FirstEventID: input.FirstEventID, LastEventID: input.LastEventID, ChainDigest: string(chain.RangeDigest),
			InstanceID: chain.Links[0].InstanceID, FirstSegmentSequence: chain.Links[0].SegmentSequence, LastSegmentSequence: chain.Links[len(chain.Links)-1].SegmentSequence,
			SignerReferenceID: "unresolved-signer", SignerMaterialVersion: "unresolved-material", Status: "pending", ReasonCode: "declaration-draft",
			PreAnchor: chain.Links[0].PreAnchor, SourceKind: "local", ProofClass: "fixture", VerificationStatus: "pending", RecoveryEpoch: input.RecoveryEpoch,
		}
		checkpointRaw, marshalErr := json.Marshal(checkpoint)
		if marshalErr != nil || generated.ValidateContractJSON(generated.SchemaIDAuditCheckpoint, checkpointRaw, generated.ContractExact) != nil {
			app.operationFailure(writer, operation, requestID, apiFailure(generated.ErrorCodeIntegrityFailure, "audit-checkpoint-projection"))
			return
		}
		app.operationSuccess(writer, operation, requestID, value.Changed, value.Document.StateRevision, value.Document.RecoveryEpoch, checkpoint)
	}
}
