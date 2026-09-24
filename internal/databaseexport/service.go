// Package databaseexport owns inert, provider-neutral sanitized database
// export drafts. It records intent through the normal declaration authority;
// it never reads SQLite directly or writes an export artifact.
package databaseexport

import (
	"context"
	"encoding/json"
	"time"

	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type RevisionReader interface {
	CurrentRevision(context.Context) (store.RevisionToken, error)
}

type DeclarationService interface {
	Revise(context.Context, change.AuthorScope, generated.DeclarationRevisionRequest) (change.Result, error)
}

type Service struct {
	revisions    RevisionReader
	declarations DeclarationService
}

func NewService(revisions RevisionReader, declarations DeclarationService) (*Service, error) {
	if revisions == nil || declarations == nil {
		return nil, failure.New(generated.ErrorCodeInputInvalid, "database-export-service", false)
	}
	return &Service{revisions: revisions, declarations: declarations}, nil
}

func (service *Service) Draft(ctx context.Context, input generated.DatabaseExportRequest, author change.AuthorScope) (generated.DatabaseExportDraftSubmission, bool, error) {
	raw, err := json.Marshal(input)
	if service == nil || err != nil || generated.ValidateContractJSON(generated.SchemaIDDatabaseExportRequest, raw, generated.ContractExact) != nil {
		return generated.DatabaseExportDraftSubmission{}, false, failure.New(generated.ErrorCodeInputInvalid, "database-export-request", false)
	}
	current, err := service.revisions.CurrentRevision(ctx)
	if err != nil {
		return generated.DatabaseExportDraftSubmission{}, false, err
	}
	if current.StateRevision != input.ExpectedStateRevision || current.RecoveryEpoch != input.RecoveryEpoch {
		return generated.DatabaseExportDraftSubmission{}, false, failure.New(generated.ErrorCodeStateConflict, "database-export-revision", true)
	}
	request := generated.DeclarationRevisionRequest{
		Schema: generated.SchemaIDDeclarationRevisionRequest, SchemaVersion: "1.0.0",
		DeclarationID: input.ExportID, DeclarationType: "database.export",
		ExpectedRevision: 1, ExpectedStateRevision: input.ExpectedStateRevision, RecoveryEpoch: input.RecoveryEpoch,
		Operations:   []generated.DeclarationOperation{{Sequence: 1, OperationID: input.IdempotencyKey, OperationType: "database.export.prepare", AdapterID: "core.database", TargetID: "database", InputDigest: input.TargetDigest, ArtifactDigest: input.TargetDigest, Idempotent: true}},
		ReasonDigest: input.TargetDigest, Extensions: []generated.ContractExtension{},
	}
	result, err := service.declarations.Revise(ctx, author, request)
	if err != nil {
		return generated.DatabaseExportDraftSubmission{}, false, err
	}
	_, err = time.Parse(time.RFC3339, result.Document.CreatedAt)
	if err != nil {
		return generated.DatabaseExportDraftSubmission{}, false, failure.New(generated.ErrorCodeIntegrityFailure, "database-export-created-at", false)
	}
	data := generated.DatabaseExportDraftSubmission{Schema: generated.SchemaIDDatabaseExportDraftSubmission, SchemaVersion: "1.0.0", DraftID: result.Document.DeclarationID, ChangeID: result.Document.ContentDigest, ExportID: input.ExportID, Kind: input.Kind, Status: "draft", SafeNextAction: "create and authorize an exact export plan", StateRevision: result.Document.StateRevision, RecoveryEpoch: result.Document.RecoveryEpoch}
	return data, result.Changed, nil
}
