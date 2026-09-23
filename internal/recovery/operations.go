package recovery

import (
	"context"
	"encoding/json"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type RestoreQualification struct {
	Request generated.RestoreRequest
	Binding generated.RestoreBinding
}

type RestorePlanner interface {
	CreateRestorePlan(context.Context, generated.RestoreRequest, VerifiedSource, FenceResult, AuditContinuity, identity.Principal) (generated.RestoreBinding, error)
	RestoreQualification(context.Context, string) (RestoreQualification, error)
	RestoreAuthorizationPlan(context.Context, string) (generated.Plan, error)
}

type RestoreSessionCoordinator interface {
	CreateRestoreSession(context.Context, generated.RestoreBinding, store.RevisionToken) error
	TransitionRestore(context.Context, generated.RestoreBinding, string, string, string, store.RevisionToken) error
	RestoreStatus(context.Context, string) (generated.BrowserRestoreStatus, error)
}

type RestoreCandidateStager interface {
	StageRestoreCandidate(context.Context, generated.RestoreBinding, VerifiedSource, FenceResult, store.RevisionToken) (CandidateReceipt, error)
}

type RestoreCanaryRunner interface {
	Verify(context.Context, CanaryRequest) (generated.RestoreCanaryResult, error)
}

type OperationsConfig struct {
	Sources              SourceVerifier
	Continuity           ContinuityResolver
	Fences               FenceEvaluator
	Plans                RestorePlanner
	Sessions             RestoreSessionCoordinator
	Candidates           RestoreCandidateStager
	Canary               RestoreCanaryRunner
	TargetReleaseBuildID string
	TargetToolVersion    string
	TargetSchemaVersion  string
}

type OperationsService struct{ config OperationsConfig }

func NewOperationsService(config OperationsConfig) (*OperationsService, error) {
	if config.Sources.Clock == nil || config.Fences.Clock == nil || config.Plans == nil || config.Sessions == nil || config.Candidates == nil || config.Canary == nil || config.TargetReleaseBuildID == "" || config.TargetToolVersion == "" || config.TargetSchemaVersion == "" {
		return nil, failure.New(generated.ErrorCodeInputInvalid, "restore-operations", false)
	}
	return &OperationsService{config: config}, nil
}

func (service *OperationsService) Plan(ctx context.Context, request generated.RestoreRequest, principal identity.Principal) (generated.RestoreBinding, error) {
	if service == nil || principal.ID == "" {
		return generated.RestoreBinding{}, failure.New(generated.ErrorCodeInputInvalid, "restore-plan", false)
	}
	source, fences, continuity, err := service.qualify(ctx, request)
	if err != nil {
		return generated.RestoreBinding{}, err
	}
	return service.config.Plans.CreateRestorePlan(ctx, request, source, fences, continuity, principal)
}

func (service *OperationsService) Run(ctx context.Context, request generated.RestoreRunRequest, principal identity.Principal) (generated.RestoreBinding, error) {
	if service == nil || principal.ID == "" {
		return generated.RestoreBinding{}, failure.New(generated.ErrorCodeInputInvalid, "restore-run", false)
	}
	qualification, err := service.config.Plans.RestoreQualification(ctx, request.PlanID)
	if err != nil || request.HumanAcknowledgementID == "" || request.HumanAcknowledgementID == "pending-human-acknowledgement" || !runMatchesBinding(request, qualification.Binding) {
		return generated.RestoreBinding{}, failure.New(generated.ErrorCodePlanStale, "restore-run", false)
	}
	executionBinding := qualification.Binding
	executionBinding.HumanAcknowledgementID = request.HumanAcknowledgementID
	source, fences, continuity, err := service.qualify(ctx, qualification.Request)
	if err != nil {
		return generated.RestoreBinding{}, err
	}
	if continuity.DecisionDigest != executionBinding.AuditDecisionDigest || fences.FenceSetDigest != executionBinding.FenceSetDigest {
		return generated.RestoreBinding{}, failure.New(generated.ErrorCodePlanStale, "restore-run", false)
	}
	expected := store.RevisionToken{StateRevision: request.ExpectedStateRevision, RecoveryEpoch: request.RecoveryEpoch}
	if err := service.config.Sessions.CreateRestoreSession(ctx, executionBinding, expected); err != nil {
		return generated.RestoreBinding{}, err
	}
	if err := service.config.Sessions.TransitionRestore(ctx, executionBinding, "planned", "fenced", fences.FenceSetDigest, expected); err != nil {
		return generated.RestoreBinding{}, err
	}
	if _, err := service.config.Candidates.StageRestoreCandidate(ctx, executionBinding, source, fences, expected); err != nil {
		return generated.RestoreBinding{}, err
	}
	if err := service.config.Sessions.TransitionRestore(ctx, executionBinding, "fenced", "restoring", executionBinding.CandidateDigest, expected); err != nil {
		return generated.RestoreBinding{}, err
	}
	if err := service.config.Sessions.TransitionRestore(ctx, executionBinding, "restoring", "verification-required", executionBinding.CandidateDigest, expected); err != nil {
		return generated.RestoreBinding{}, err
	}
	return executionBinding, nil
}

func (service *OperationsService) Verify(ctx context.Context, request generated.RestoreVerifyRequest, principal identity.Principal) (generated.RestoreVerification, error) {
	if service == nil || principal.ID == "" {
		return generated.RestoreVerification{}, failure.New(generated.ErrorCodeInputInvalid, "restore-verify", false)
	}
	qualification, err := service.config.Plans.RestoreQualification(ctx, request.PlanID)
	if err != nil || !verifyMatchesBinding(request, qualification.Binding) {
		return generated.RestoreVerification{}, failure.New(generated.ErrorCodePlanStale, "restore-verify", false)
	}
	canary, err := service.config.Canary.Verify(ctx, CanaryRequest{PlanID: request.PlanID, PlanDigest: request.PlanDigest, NewInstanceID: request.NewInstanceID, FenceSetDigest: request.FenceSetDigest, RecoveryEpoch: request.NextRecoveryEpoch, ExpectedStateRevision: request.ExpectedStateRevision})
	if err != nil {
		return generated.RestoreVerification{}, err
	}
	stamp := canary.VerifiedAt
	result := generated.RestoreVerification{Schema: generated.SchemaIDRestoreVerification, SchemaVersion: "1.1.0", Source: request.Source, PlanID: request.PlanID, PlanDigest: request.PlanDigest, PointID: request.PointID, TargetDigest: request.TargetDigest, FenceVerified: true, DatabaseVerified: true, AuditVerified: true, VerifiedAt: stamp, PriorInstanceID: request.PriorInstanceID, NewInstanceID: request.NewInstanceID, PriorRecoveryEpoch: request.PriorRecoveryEpoch, NextRecoveryEpoch: request.NextRecoveryEpoch, FenceSetDigest: request.FenceSetDigest, AuditDecisionDigest: request.AuditDecisionDigest, CandidateDigest: request.CandidateDigest, Canary: canary, Status: "verified"}
	raw, marshalErr := json.Marshal(result)
	if marshalErr != nil || generated.ValidateContractJSON(generated.SchemaIDRestoreVerification, raw, generated.ContractExact) != nil {
		return generated.RestoreVerification{}, failure.New(generated.ErrorCodeIntegrityFailure, "restore-verification", false)
	}
	return result, nil
}

func (service *OperationsService) Get(ctx context.Context, planID string) (generated.BrowserRestoreStatus, error) {
	return service.config.Sessions.RestoreStatus(ctx, planID)
}

func (service *OperationsService) AuthorizationPlan(ctx context.Context, planID string) (generated.Plan, error) {
	return service.config.Plans.RestoreAuthorizationPlan(ctx, planID)
}

func (service *OperationsService) qualify(ctx context.Context, request generated.RestoreRequest) (VerifiedSource, FenceResult, AuditContinuity, error) {
	selection := SourceSelection{PointID: request.PointID, SourceClass: request.Source.SourceClass, RepositoryClass: repositoryClass(request.Source.SourceClass), DeclaredRPOSeconds: request.Source.DeclaredRPOSeconds, TargetReleaseBuildID: service.config.TargetReleaseBuildID, TargetToolVersion: service.config.TargetToolVersion, TargetSchemaVersion: service.config.TargetSchemaVersion}
	source, err := service.config.Sources.Verify(ctx, selection)
	if err != nil {
		return VerifiedSource{}, FenceResult{}, AuditContinuity{}, err
	}
	continuity, err := service.config.Continuity.Resolve(ctx, source, &request.AuditDecision)
	if err != nil {
		return VerifiedSource{}, FenceResult{}, AuditContinuity{}, err
	}
	requirements, err := service.config.Fences.Requirements(ctx, source, request.PriorInstanceID)
	if err != nil {
		return VerifiedSource{}, FenceResult{}, AuditContinuity{}, err
	}
	fences, err := service.config.Fences.Verify(ctx, requirements)
	if err != nil {
		return VerifiedSource{}, FenceResult{}, AuditContinuity{}, err
	}
	if !sameJSONValue(source.Binding, request.Source) || !sameJSONValue(fences.Items, request.Fences) || fences.FenceSetDigest != request.FenceSetDigest || continuity.DecisionDigest != request.AuditDecisionDigest {
		return VerifiedSource{}, FenceResult{}, AuditContinuity{}, failure.New(generated.ErrorCodePlanStale, "restore-qualification", false)
	}
	return source, fences, continuity, nil
}

func repositoryClass(sourceClass string) string {
	if sourceClass == "off-site" {
		return "critical"
	}
	return "standard"
}

func sameJSONValue(left, right any) bool {
	a, _ := json.Marshal(left)
	b, _ := json.Marshal(right)
	return string(a) == string(b)
}

func runMatchesBinding(request generated.RestoreRunRequest, binding generated.RestoreBinding) bool {
	return request.PlanID == binding.PlanID && request.PlanDigest == binding.PlanDigest && request.PointID == binding.PointID && request.TargetDigest == binding.TargetDigest && request.FenceSetDigest == binding.FenceSetDigest && request.AuditDecisionDigest == binding.AuditDecisionDigest && request.CandidateDigest == binding.CandidateDigest && request.PriorInstanceID == binding.PriorInstanceID && request.NewInstanceID == binding.NewInstanceID && request.PriorRecoveryEpoch == binding.PriorRecoveryEpoch && request.NextRecoveryEpoch == binding.NextRecoveryEpoch && sameJSONValue(request.Source, binding.Source)
}

func verifyMatchesBinding(request generated.RestoreVerifyRequest, binding generated.RestoreBinding) bool {
	return request.PlanID == binding.PlanID && request.PlanDigest == binding.PlanDigest && request.PointID == binding.PointID && request.TargetDigest == binding.TargetDigest && request.FenceSetDigest == binding.FenceSetDigest && request.AuditDecisionDigest == binding.AuditDecisionDigest && request.CandidateDigest == binding.CandidateDigest && request.PriorInstanceID == binding.PriorInstanceID && request.NewInstanceID == binding.NewInstanceID && request.PriorRecoveryEpoch == binding.PriorRecoveryEpoch && request.NextRecoveryEpoch == binding.NextRecoveryEpoch && sameJSONValue(request.Source, binding.Source)
}
