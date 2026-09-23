package recovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	planengine "github.com/vegastack/vegastack-labs/internal/plan"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type StoreRestorePlanner struct {
	Declarations *store.DeclarationRepository
	Plans        *store.PlanRepository
	Restores     *store.RestoreRepository
	Clock        func() time.Time
}

func (planner StoreRestorePlanner) CreateRestorePlan(ctx context.Context, request generated.RestoreRequest, source VerifiedSource, fences FenceResult, continuity AuditContinuity, principal identity.Principal) (generated.RestoreBinding, error) {
	if planner.Declarations == nil || planner.Plans == nil || planner.Restores == nil || principal.ID == "" || principal.Method == "" || continuity.DecisionDigest != request.AuditDecisionDigest {
		return generated.RestoreBinding{}, failure.New(generated.ErrorCodeInputInvalid, "restore-plan", false)
	}
	document, err := change.BuildRestoreChange(ctx, request, source.Binding, fences.Items, request.AuditDecision)
	if err != nil {
		return generated.RestoreBinding{}, err
	}
	clock := planner.Clock
	if clock == nil {
		clock = time.Now
	}
	now := clock().UTC()
	if now.IsZero() {
		return generated.RestoreBinding{}, failure.New(generated.ErrorCodePrerequisiteBlocked, "restore-plan-clock", false)
	}
	document.CreatedAt, document.CreatedBy, document.AgentSessionID = now.Truncate(time.Second).Format(time.RFC3339), principal.ID, "restore-plan"
	requestBytes, _ := json.Marshal(request)
	stored, err := planner.Declarations.CreateRevision(ctx, store.DeclarationRevisionRequest{Document: document, ReasonDigest: request.AuditDecisionDigest, Expected: store.RevisionToken{StateRevision: request.ExpectedStateRevision, RecoveryEpoch: request.RecoveryEpoch}, KeyDigest: semanticDigest([]byte("restore-declaration\x00" + request.IdempotencyKey)), RequestDigest: semanticDigest(requestBytes), Attribution: audit.Attribution{AuthenticatedPrincipalID: principal.ID, AuthenticatedPrincipalMethod: principal.Method}})
	if err != nil {
		return generated.RestoreBinding{}, err
	}
	value, binding, err := planengine.BuildRestorePlan(ctx, stored.Document, request, source.Binding, fences.Items, request.AuditDecision)
	if err != nil {
		return generated.RestoreBinding{}, err
	}
	canonical, readable, err := planengine.RestorePlanArtifacts(value)
	if err != nil {
		return generated.RestoreBinding{}, err
	}
	desired := stored.Document
	desired.Revision = value.Binding.DeclarationRevision
	desired.StateRevision = value.Binding.StateRevision
	desired.Status = "committed"
	planRequestBytes, _ := json.Marshal(struct {
		Request generated.RestoreRequest
		PlanID  string
	}{request, value.PlanID})
	committed, err := planner.Plans.CommitDeclarationAndPlan(ctx, store.PlanCommitRequest{Plan: value, DesiredDeclaration: desired, SourceDeclarationRevision: stored.Document.Revision, ReasonDigest: request.AuditDecisionDigest, CanonicalBytes: canonical, Readable: readable, Expected: store.RevisionToken{StateRevision: value.Binding.PriorStateRevision, RecoveryEpoch: value.Binding.RecoveryEpoch}, KeyDigest: semanticDigest([]byte("restore-plan\x00" + request.IdempotencyKey)), RequestDigest: semanticDigest(planRequestBytes), Attribution: audit.Attribution{AuthenticatedPrincipalID: principal.ID, AuthenticatedPrincipalMethod: principal.Method}, RestoreQualification: &store.RestorePlanQualification{Request: request, Binding: binding}})
	if err != nil {
		return generated.RestoreBinding{}, err
	}
	if committed.Plan.PlanID != binding.PlanID || committed.Plan.PlanDigest != binding.PlanDigest {
		return generated.RestoreBinding{}, failure.New(generated.ErrorCodeIntegrityFailure, "restore-plan", false)
	}
	return binding, nil
}

func (planner StoreRestorePlanner) RestoreQualification(ctx context.Context, planID string) (RestoreQualification, error) {
	stored, err := planner.Restores.Qualification(ctx, planID)
	return RestoreQualification{Request: stored.Request, Binding: stored.Binding}, err
}

func (planner StoreRestorePlanner) RestoreAuthorizationPlan(ctx context.Context, planID string) (generated.Plan, error) {
	stored, err := planner.Plans.GetPlan(ctx, planID)
	return stored.Plan, err
}

type StoreRestoreSessions struct{ Repository *store.RestoreRepository }

func (sessions StoreRestoreSessions) CreateRestoreSession(ctx context.Context, binding generated.RestoreBinding, expected store.RevisionToken) error {
	_, err := sessions.Repository.CreatePlan(ctx, store.RestorePlanRequest{Binding: binding, Expected: expected})
	return err
}

func (sessions StoreRestoreSessions) TransitionRestore(ctx context.Context, binding generated.RestoreBinding, from, to, evidence string, expected store.RevisionToken) error {
	return sessions.Repository.AppendTransition(ctx, store.RestoreTransitionRequest{PlanID: binding.PlanID, From: from, To: to, PlanDigest: binding.PlanDigest, EvidenceDigest: evidence, Expected: expected})
}

func (sessions StoreRestoreSessions) RestoreStatus(ctx context.Context, planID string) (generated.BrowserRestoreStatus, error) {
	stored, err := sessions.Repository.Get(ctx, planID)
	if err != nil {
		return generated.BrowserRestoreStatus{}, err
	}
	verification := "pending"
	if stored.Status == "verified" {
		verification = "verified"
	}
	return generated.BrowserRestoreStatus{Schema: generated.SchemaIDBrowserRestoreStatus, SchemaVersion: "1.0.0", PointID: stored.Binding.PointID, PlanID: stored.Binding.PlanID, PlanDigest: stored.Binding.PlanDigest, TargetDigest: stored.Binding.TargetDigest, Status: stored.Status, RecoveryEpoch: stored.Binding.NextRecoveryEpoch, VerificationStatus: verification}, nil
}

type StoreCandidateStager struct {
	Manager    CandidateManager
	Repository *store.RestoreRepository
}

func (stager StoreCandidateStager) StageRestoreCandidate(ctx context.Context, binding generated.RestoreBinding, source VerifiedSource, fences FenceResult, expected store.RevisionToken) (CandidateReceipt, error) {
	manager := stager.Manager
	manager.Records = StoreCandidateRecorder{Repository: stager.Repository, Expected: expected, PreservedAuthorityDigest: semanticDigest(mustJSON(struct {
		InstanceID string
		Revision   store.RevisionToken
	}{binding.PriorInstanceID, expected}))}
	return manager.Stage(ctx, binding, source, fences)
}

func semanticDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func mustJSON(value any) []byte {
	raw, _ := json.Marshal(value)
	return raw
}
