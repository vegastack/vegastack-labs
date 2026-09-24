package recovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
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
	if store.Code(err) == generated.ErrorCodeResourceNotFound {
		bundle, _, bundleErr := planner.Restores.RecoveredAuthorityBundle(ctx, planID)
		return RestoreQualification{Request: bundle.Request, Binding: bundle.Binding}, bundleErr
	}
	return RestoreQualification{Request: stored.Request, Binding: stored.Binding}, err
}

func (planner StoreRestorePlanner) RestoreAuthorizationPlan(ctx context.Context, planID string) (generated.Plan, error) {
	stored, err := planner.Plans.GetPlan(ctx, planID)
	if store.Code(err) == generated.ErrorCodeResourceNotFound {
		bundle, _, bundleErr := planner.Restores.RecoveredAuthorityBundle(ctx, planID)
		return bundle.Plan, bundleErr
	}
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
		if store.Code(err) != generated.ErrorCodeResourceNotFound {
			return generated.BrowserRestoreStatus{}, err
		}
		bundle, _, bundleErr := sessions.Repository.RecoveredAuthorityBundle(ctx, planID)
		if bundleErr != nil {
			return generated.BrowserRestoreStatus{}, bundleErr
		}
		verification := "pending"
		if bundle.Status == "verified" {
			verification = "verified"
		}
		return generated.BrowserRestoreStatus{Schema: generated.SchemaIDBrowserRestoreStatus, SchemaVersion: "1.0.0", PointID: bundle.Binding.PointID, PlanID: bundle.Binding.PlanID, PlanDigest: bundle.Binding.PlanDigest, TargetDigest: bundle.Binding.TargetDigest, Status: bundle.Status, ReasonCode: "restore-" + bundle.Status, RecoveryEpoch: bundle.Binding.NextRecoveryEpoch, VerificationStatus: verification, SafeNextAction: restoreSafeNextAction(bundle.Status)}, nil
	}
	verification := "pending"
	if stored.Status == "verified" {
		verification = "verified"
	}
	return generated.BrowserRestoreStatus{Schema: generated.SchemaIDBrowserRestoreStatus, SchemaVersion: "1.0.0", PointID: stored.Binding.PointID, PlanID: stored.Binding.PlanID, PlanDigest: stored.Binding.PlanDigest, TargetDigest: stored.Binding.TargetDigest, Status: stored.Status, ReasonCode: "restore-" + stored.Status, RecoveryEpoch: stored.Binding.NextRecoveryEpoch, VerificationStatus: verification, SafeNextAction: restoreSafeNextAction(stored.Status)}, nil
}

func restoreSafeNextAction(status string) string {
	switch status {
	case "verified":
		return "none"
	case "verification-required":
		return "verify the recovered authority"
	default:
		return "continue with the exact approved restore plan"
	}
}

func (sessions StoreRestoreSessions) ListRestoreStatuses(ctx context.Context, scope authorization.ReadScope, snapshot store.RevisionToken, afterID string, limit int) ([]generated.BrowserRestoreStatus, store.RevisionToken, error) {
	return sessions.Repository.ListRestoreStatusesScoped(ctx, scope, snapshot, afterID, limit)
}

func (sessions StoreRestoreSessions) RestoreExecutionStatus(ctx context.Context, planID string) (string, error) {
	stored, err := sessions.Repository.Get(ctx, planID)
	return stored.Status, err
}

type StoreCandidateStager struct {
	Manager    CandidateManager
	Repository *store.RestoreRepository
	Plans      *store.PlanRepository
}

func (stager StoreCandidateStager) StageRestoreCandidate(ctx context.Context, binding generated.RestoreBinding, source VerifiedSource, fences FenceResult, expected store.RevisionToken) (CandidateReceipt, error) {
	if existing, err := stager.Repository.Get(ctx, binding.PlanID); err == nil && existing.Candidate != nil {
		candidate := existing.Candidate
		if candidate.CandidateDigest != binding.CandidateDigest || candidate.FenceSetDigest != binding.FenceSetDigest || candidate.AuditDecisionDigest != binding.AuditDecisionDigest || candidate.Expected != expected {
			return CandidateReceipt{}, failure.New(generated.ErrorCodeStateConflict, "recovery-candidate", false)
		}
		return CandidateReceipt{PlanID: binding.PlanID, CandidateDigest: candidate.CandidateDigest, DatabaseDigest: candidate.DatabaseDigest, JournalDigest: candidate.JournalDigest, BundleDigest: candidate.BundleDigest, NewInstanceID: binding.NewInstanceID, NextRecoveryEpoch: binding.NextRecoveryEpoch}, nil
	}
	manager := stager.Manager
	if bundles, ok := manager.Bundles.(StoreRecoveryBundleStore); ok {
		bundles.Plans = stager.Plans
		bundles.Restores = stager.Repository
		manager.Bundles = bundles
	}
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
