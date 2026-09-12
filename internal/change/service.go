package change

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/stateexport"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type Repository interface {
	CreateRevision(context.Context, store.DeclarationRevisionRequest) (store.DeclarationRevisionResult, error)
	GetRevision(context.Context, string, int64) (generated.DeclarationRevision, error)
}

func (service *Service) Get(ctx context.Context, declarationID string, revision int64) (generated.DeclarationRevision, error) {
	if service == nil || declarationID == "" || revision < 1 {
		return generated.DeclarationRevision{}, inputError()
	}
	return service.repository.GetRevision(ctx, declarationID, revision)
}

type Service struct {
	repository Repository
	clock      func() time.Time
}

func NewService(repository Repository, clock func() time.Time) (*Service, error) {
	if repository == nil {
		return nil, inputError()
	}
	if clock == nil {
		clock = time.Now
	}
	return &Service{repository: repository, clock: clock}, nil
}

func (service *Service) Revise(ctx context.Context, author AuthorScope, request generated.DeclarationRevisionRequest) (Result, error) {
	if service == nil || service.repository == nil || author.PrincipalID == "" || author.PrincipalMethod == "" || author.AgentSessionID == "" {
		return Result{}, inputError()
	}
	rawRequest, err := json.Marshal(request)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDDeclarationRevisionRequest, rawRequest, generated.ContractExact) != nil {
		return Result{}, inputError()
	}
	operations := append([]generated.DeclarationOperation(nil), request.Operations...)
	sort.Slice(operations, func(i, j int) bool { return operations[i].Sequence < operations[j].Sequence })
	for index := range operations {
		if operations[index].Sequence != int64(index+1) {
			return Result{}, inputError()
		}
	}
	extensions := append(make([]generated.ContractExtension, 0, len(request.Extensions)), request.Extensions...)
	sort.Slice(extensions, func(i, j int) bool { return extensions[i].Name < extensions[j].Name })
	semantic := struct {
		DeclarationID   string                           `json:"declarationId"`
		DeclarationType string                           `json:"declarationType"`
		Operations      []generated.DeclarationOperation `json:"operations"`
		ReasonDigest    string                           `json:"reasonDigest"`
		Extensions      []generated.ContractExtension    `json:"extensions"`
	}{request.DeclarationID, request.DeclarationType, operations, request.ReasonDigest, extensions}
	_, contentSum, err := stateexport.CanonicalJSON(semantic)
	if err != nil {
		return Result{}, inputError()
	}
	document := generated.DeclarationRevision{Schema: generated.SchemaIDDeclarationRevision, SchemaVersion: "1.0.0", DeclarationID: request.DeclarationID, DeclarationType: request.DeclarationType, Revision: request.ExpectedRevision, StateRevision: request.ExpectedStateRevision + 1, RecoveryEpoch: request.RecoveryEpoch, ContentDigest: digest(contentSum), Status: "draft", Operations: operations, CreatedAt: service.clock().UTC().Truncate(time.Second).Format(time.RFC3339), CreatedBy: author.PrincipalID, AgentSessionID: author.AgentSessionID, Extensions: extensions}
	_, requestSum, err := stateexport.CanonicalJSON(request)
	if err != nil {
		return Result{}, inputError()
	}
	keySum := sha256.Sum256([]byte(request.DeclarationID + ":" + fmt.Sprintf("%d", request.ExpectedRevision)))
	attribution := audit.Attribution{AuthenticatedPrincipalID: author.PrincipalID, AuthenticatedPrincipalMethod: author.PrincipalMethod}
	if author.AgentName != "" {
		attribution.Agent = &audit.AgentMetadata{Name: author.AgentName, SessionID: author.AgentSessionID}
	}
	stored, err := service.repository.CreateRevision(ctx, store.DeclarationRevisionRequest{Document: document, ReasonDigest: request.ReasonDigest, Expected: store.RevisionToken{StateRevision: request.ExpectedStateRevision, RecoveryEpoch: request.RecoveryEpoch}, KeyDigest: digest(keySum), RequestDigest: digest(requestSum), Attribution: attribution})
	if err != nil {
		return Result{}, err
	}
	return Result{Document: stored.Document, Changed: stored.Commit.Changed, Created: stored.Created}, nil
}

func digest(sum [32]byte) string { return "sha256:" + hex.EncodeToString(sum[:]) }
func inputError() error          { return failure.New(generated.ErrorCodeInputInvalid, "declaration", false) }
