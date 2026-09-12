// Package plan constructs immutable provider-neutral plans without invoking adapters.
package plan

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/stateexport"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type AuthorScope struct {
	PrincipalID     string
	PrincipalMethod string
	AgentName       string
	AgentSessionID  string
}

type ObservationReader interface {
	CurrentFingerprint(context.Context, string, []generated.DeclarationOperation) (string, error)
}

type Repository interface {
	GetDeclaration(context.Context, string, int64) (generated.DeclarationRevision, error)
	GetDeclarationReason(context.Context, string, int64) (string, error)
	CurrentRevision(context.Context) (store.RevisionToken, error)
	ExistingPlan(context.Context, string, string) (store.PlanCommitResult, bool, error)
	GetPlan(context.Context, string) (store.PlanCommitResult, error)
	CommitDeclarationAndPlan(context.Context, store.PlanCommitRequest) (store.PlanCommitResult, error)
}

type Config struct {
	Repository          Repository
	Observations        ObservationReader
	Clock               func() time.Time
	PolicyVersion       string
	ToolVersion         string
	ContractVersion     string
	Risk                string
	AuthorizationBranch string
	ExecutorMode        string
	ExecutorID          *string
	OperationExecutorID string
}

type Service struct{ config Config }

func NewService(config Config) (*Service, error) {
	if config.Repository == nil || config.Observations == nil || config.PolicyVersion == "" || config.ToolVersion == "" || config.ContractVersion == "" || config.Risk == "" || config.AuthorizationBranch == "" || config.ExecutorMode == "" || config.OperationExecutorID == "" {
		return nil, planError(generated.ErrorCodeInputInvalid)
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	return &Service{config: config}, nil
}

func (service *Service) Create(ctx context.Context, author AuthorScope, request generated.PlanCreateRequest) (store.PlanCommitResult, error) {
	if service == nil || author.PrincipalID == "" || author.PrincipalMethod == "" {
		return store.PlanCommitResult{}, planError(generated.ErrorCodeInputInvalid)
	}
	raw, err := json.Marshal(request)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDPlanCreateRequest, raw, generated.ContractExact) != nil {
		return store.PlanCommitResult{}, planError(generated.ErrorCodeInputInvalid)
	}
	extensions := append(make([]generated.ContractExtension, 0, len(request.Extensions)), request.Extensions...)
	sort.Slice(extensions, func(i, j int) bool { return extensions[i].Name < extensions[j].Name })
	for index := 1; index < len(extensions); index++ {
		if extensions[index-1].Name == extensions[index].Name {
			return store.PlanCommitResult{}, planError(generated.ErrorCodeInputInvalid)
		}
	}
	normalizedRequest := request
	normalizedRequest.Extensions = extensions
	normalized, _, err := stateexport.CanonicalJSON(normalizedRequest)
	if err != nil {
		return store.PlanCommitResult{}, planError(generated.ErrorCodeInputInvalid)
	}
	keyDigest, requestDigest := sha([]byte(request.IdempotencyKey)), sha(normalized)
	if existing, found, err := service.config.Repository.ExistingPlan(ctx, keyDigest, requestDigest); err != nil || found {
		return existing, err
	}
	declaration, err := service.config.Repository.GetDeclaration(ctx, request.DeclarationID, request.DeclarationRevision)
	if err != nil {
		return store.PlanCommitResult{}, err
	}
	if declaration.Status != "draft" || declaration.DeclarationID != request.DeclarationID || declaration.Revision != request.DeclarationRevision {
		return store.PlanCommitResult{}, planError(generated.ErrorCodeStateConflict)
	}
	reason, err := service.config.Repository.GetDeclarationReason(ctx, request.DeclarationID, request.DeclarationRevision)
	if err != nil {
		return store.PlanCommitResult{}, err
	}
	current, err := service.config.Repository.CurrentRevision(ctx)
	if err != nil {
		return store.PlanCommitResult{}, err
	}
	if current != (store.RevisionToken{StateRevision: request.ExpectedStateRevision, RecoveryEpoch: request.RecoveryEpoch}) || declaration.RecoveryEpoch != request.RecoveryEpoch {
		return store.PlanCommitResult{}, planError(generated.ErrorCodeStateConflict)
	}
	fingerprint, err := service.config.Observations.CurrentFingerprint(ctx, declaration.DeclarationID, declaration.Operations)
	if err != nil {
		return store.PlanCommitResult{}, err
	}
	if fingerprint != request.ObservationFingerprint || fingerprint == "" {
		return store.PlanCommitResult{}, planError(generated.ErrorCodeStateConflict)
	}
	declarationOperations := append([]generated.DeclarationOperation(nil), declaration.Operations...)
	sort.Slice(declarationOperations, func(i, j int) bool { return declarationOperations[i].Sequence < declarationOperations[j].Sequence })
	operations := make([]generated.PlanOperation, len(declarationOperations))
	for index, operation := range declarationOperations {
		if operation.Sequence != int64(index+1) {
			return store.PlanCommitResult{}, planError(generated.ErrorCodeInputInvalid)
		}
		operations[index] = generated.PlanOperation{Sequence: operation.Sequence, OperationID: operation.OperationID, OperationType: operation.OperationType, AdapterID: operation.AdapterID, ExecutorID: service.config.OperationExecutorID, TargetID: operation.TargetID, InputDigest: operation.InputDigest, ArtifactDigest: operation.ArtifactDigest, Idempotent: operation.Idempotent}
	}
	targets, err := targetDigest(operations)
	if err != nil {
		return store.PlanCommitResult{}, planError(generated.ErrorCodeInputInvalid)
	}
	created := service.config.Clock().UTC().Truncate(time.Second)
	desired := declaration
	desired.Revision = declaration.Revision + 1
	desired.StateRevision = current.StateRevision + 1
	desired.Status = "committed"
	desired.CreatedAt = created.Format(time.RFC3339)
	desired.CreatedBy = author.PrincipalID
	desired.AgentSessionID = author.AgentSessionID
	desired.Operations = declarationOperations
	desired.Extensions = append([]generated.ContractExtension(nil), declaration.Extensions...)
	candidate := generated.Plan{Schema: generated.SchemaIDPlan, SchemaVersion: "1.0.0", DeclarationID: declaration.DeclarationID, Binding: generated.PlanBinding{RecoveryEpoch: current.RecoveryEpoch, PriorStateRevision: current.StateRevision, StateRevision: current.StateRevision + 1, DeclarationRevision: desired.Revision, ObservationFingerprint: fingerprint, TargetDigest: targets, ReasonDigest: reason, PolicyVersion: service.config.PolicyVersion, ToolVersion: service.config.ToolVersion, ContractVersion: service.config.ContractVersion}, Operations: operations, Status: "planned", Risk: service.config.Risk, AuthorizationBranch: service.config.AuthorizationBranch, ExecutorMode: service.config.ExecutorMode, ExecutorID: service.config.ExecutorID, CreatedAt: created.Format(time.RFC3339), ExpiresAt: created.Add(time.Duration(generated.PlanValiditySeconds) * time.Second).Format(time.RFC3339), Extensions: extensions}
	readable := readablePlan(candidate)
	candidate.ReadableDigest = sha([]byte(readable))
	candidate.PlanDigest, err = planDigest(candidate)
	if err != nil {
		return store.PlanCommitResult{}, planError(generated.ErrorCodeInputInvalid)
	}
	candidate.PlanID = "plan-" + strings.TrimPrefix(candidate.PlanDigest, "sha256:")[:32]
	canonical, err := canonicalPlan(candidate)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDPlan, canonical, generated.ContractExact) != nil || generated.ValidatePlanTiming(candidate) != nil {
		return store.PlanCommitResult{}, planError(generated.ErrorCodeInputInvalid)
	}
	attribution := audit.Attribution{AuthenticatedPrincipalID: author.PrincipalID, AuthenticatedPrincipalMethod: author.PrincipalMethod}
	if author.AgentName != "" {
		attribution.Agent = &audit.AgentMetadata{Name: author.AgentName, SessionID: author.AgentSessionID}
	}
	return service.config.Repository.CommitDeclarationAndPlan(ctx, store.PlanCommitRequest{Plan: candidate, DesiredDeclaration: desired, SourceDeclarationRevision: declaration.Revision, ReasonDigest: reason, CanonicalBytes: canonical, Readable: readable, Expected: current, KeyDigest: keyDigest, RequestDigest: requestDigest, Attribution: attribution})
}

func (service *Service) ValidateCurrent(ctx context.Context, candidate generated.Plan) error {
	if generated.ValidatePlanTiming(candidate) != nil || !service.config.Clock().UTC().Before(parseTime(candidate.ExpiresAt)) {
		return planError(generated.ErrorCodeStateConflict)
	}
	current, err := service.config.Repository.CurrentRevision(ctx)
	if err != nil {
		return err
	}
	if current.StateRevision != candidate.Binding.StateRevision || current.RecoveryEpoch != candidate.Binding.RecoveryEpoch {
		return planError(generated.ErrorCodeStateConflict)
	}
	declaration, err := service.config.Repository.GetDeclaration(ctx, candidate.DeclarationID, candidate.Binding.DeclarationRevision)
	if err != nil {
		return err
	}
	fingerprint, err := service.config.Observations.CurrentFingerprint(ctx, declaration.DeclarationID, declaration.Operations)
	if err != nil {
		return err
	}
	if fingerprint != candidate.Binding.ObservationFingerprint {
		return planError(generated.ErrorCodeStateConflict)
	}
	return nil
}

func (service *Service) Get(ctx context.Context, planID string) (store.PlanCommitResult, error) {
	if service == nil || planID == "" {
		return store.PlanCommitResult{}, planError(generated.ErrorCodeInputInvalid)
	}
	return service.config.Repository.GetPlan(ctx, planID)
}

func parseTime(value string) time.Time { parsed, _ := time.Parse(time.RFC3339, value); return parsed }
func planError(code string) error      { return failure.New(code, "plan", false) }
