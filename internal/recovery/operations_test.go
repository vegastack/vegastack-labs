package recovery

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type restorePlannerStub struct {
	qualification RestoreQualification
	created       int
}

func (stub *restorePlannerStub) CreateRestorePlan(_ context.Context, request generated.RestoreRequest, _ VerifiedSource, _ FenceResult, _ AuditContinuity, _ identity.Principal) (generated.RestoreBinding, error) {
	stub.created++
	return stub.qualification.Binding, nil
}
func (stub *restorePlannerStub) RestoreQualification(context.Context, string) (RestoreQualification, error) {
	return stub.qualification, nil
}
func (stub *restorePlannerStub) RestoreAuthorizationPlan(context.Context, string) (generated.Plan, error) {
	return generated.Plan{}, nil
}

type restoreSessionsStub struct{ transitions []string }

func (stub *restoreSessionsStub) CreateRestoreSession(context.Context, generated.RestoreBinding, store.RevisionToken) error {
	stub.transitions = append(stub.transitions, "session")
	return nil
}
func (stub *restoreSessionsStub) TransitionRestore(_ context.Context, _ generated.RestoreBinding, from, to, _ string, _ store.RevisionToken) error {
	stub.transitions = append(stub.transitions, from+">"+to)
	return nil
}
func (stub *restoreSessionsStub) RestoreStatus(context.Context, string) (generated.BrowserRestoreStatus, error) {
	return generated.BrowserRestoreStatus{}, nil
}

type restoreStagerStub struct{ calls int }

func (stub *restoreStagerStub) StageRestoreCandidate(_ context.Context, binding generated.RestoreBinding, source VerifiedSource, fences FenceResult, _ store.RevisionToken) (CandidateReceipt, error) {
	stub.calls++
	return CandidateReceipt{PlanID: binding.PlanID, CandidateDigest: binding.CandidateDigest, DatabaseDigest: source.DatabaseDigest, JournalDigest: testCandidateDigest("8"), NewInstanceID: binding.NewInstanceID, NextRecoveryEpoch: binding.NextRecoveryEpoch}, nil
}

type restoreCanaryStub struct{}

func (restoreCanaryStub) Verify(context.Context, CanaryRequest) (generated.RestoreCanaryResult, error) {
	stamp := "2026-09-24T06:00:00Z"
	return generated.RestoreCanaryResult{Schema: generated.SchemaIDRestoreCanaryResult, SchemaVersion: "1.1.0", ReadVerified: true, OldEpochDenied: true, NoopRunID: "run-canary", AuditCheckpointID: "checkpoint-canary", BackupPointID: "point-canary", FormerWriterDenied: true, Status: "verified", VerifiedAt: &stamp}, nil
}

func TestOperationsPlanRecomputesQualificationAndRejectsCallerMismatch(t *testing.T) {
	service, request, planner, _, _ := operationsFixture(t)
	request.Source.PointDigest = testCandidateDigest("7")
	if _, err := service.Plan(context.Background(), request, identity.Principal{ID: "human-a", Method: identity.LocalOSPeerMethod}); failureCode(err) != generated.ErrorCodePlanStale {
		t.Fatalf("mismatched source err=%v", err)
	}
	if planner.created != 0 {
		t.Fatal("planner called before qualification matched")
	}
}

func TestOperationsRunRequalifiesBeforeStagingExactCandidate(t *testing.T) {
	service, request, _, sessions, stager := operationsFixture(t)
	binding := service.config.Plans.(*restorePlannerStub).qualification.Binding
	run := generated.RestoreRunRequest{Schema: generated.SchemaIDRestoreRunRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: request.ExpectedStateRevision + 1, RecoveryEpoch: request.RecoveryEpoch, TargetDigest: binding.TargetDigest, IdempotencyKey: "restore-run-a", Source: binding.Source, PointID: binding.PointID, PlanID: binding.PlanID, PlanDigest: binding.PlanDigest, HumanAcknowledgementID: "ack-a", FenceSetDigest: binding.FenceSetDigest, AuditDecisionDigest: binding.AuditDecisionDigest, CandidateDigest: binding.CandidateDigest, PriorInstanceID: binding.PriorInstanceID, NewInstanceID: binding.NewInstanceID, PriorRecoveryEpoch: binding.PriorRecoveryEpoch, NextRecoveryEpoch: binding.NextRecoveryEpoch}
	got, err := service.Run(context.Background(), run, identity.Principal{ID: "human-a", Method: identity.LocalOSPeerMethod})
	if err != nil {
		t.Fatal(err)
	}
	if got.PlanID != binding.PlanID || stager.calls != 1 {
		t.Fatalf("binding=%#v stage calls=%d", got, stager.calls)
	}
	want := []string{"session", "planned>fenced", "fenced>restoring", "restoring>verification-required"}
	if strings.Join(sessions.transitions, ",") != strings.Join(want, ",") {
		t.Fatalf("transitions=%v", sessions.transitions)
	}
}

func TestOperationsRunRejectsPlaceholderAcknowledgementBeforeMutation(t *testing.T) {
	service, request, _, sessions, stager := operationsFixture(t)
	binding := service.config.Plans.(*restorePlannerStub).qualification.Binding
	run := generated.RestoreRunRequest{Schema: generated.SchemaIDRestoreRunRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: request.ExpectedStateRevision + 1, RecoveryEpoch: request.RecoveryEpoch, TargetDigest: binding.TargetDigest, IdempotencyKey: "restore-run-a", Source: binding.Source, PointID: binding.PointID, PlanID: binding.PlanID, PlanDigest: binding.PlanDigest, HumanAcknowledgementID: "pending-human-acknowledgement", FenceSetDigest: binding.FenceSetDigest, AuditDecisionDigest: binding.AuditDecisionDigest, CandidateDigest: binding.CandidateDigest, PriorInstanceID: binding.PriorInstanceID, NewInstanceID: binding.NewInstanceID, PriorRecoveryEpoch: binding.PriorRecoveryEpoch, NextRecoveryEpoch: binding.NextRecoveryEpoch}
	if _, err := service.Run(context.Background(), run, identity.Principal{ID: "human-a", Method: identity.LocalOSPeerMethod}); failureCode(err) != generated.ErrorCodePlanStale {
		t.Fatalf("placeholder acknowledgement err=%v", err)
	}
	if len(sessions.transitions) != 0 || stager.calls != 0 {
		t.Fatalf("mutation before acknowledgement validation: transitions=%v stages=%d", sessions.transitions, stager.calls)
	}
}

func operationsFixture(t *testing.T) (*OperationsService, generated.RestoreRequest, *restorePlannerStub, *restoreSessionsStub, *restoreStagerStub) {
	t.Helper()
	installed, _, qualified, binding, now, _ := installedSourceFixture(t)
	record := validLocalRecoverySource(now)
	record.Verification.RecoveryEpoch = binding.PriorEpoch
	record.Point.RecoveryEpoch = binding.PriorEpoch
	auditPosition := AuditContinuity{LocalLastEventID: 4, IndependentLastEventID: 4, IndependentCheckpointDigest: testCandidateDigest("9")}
	sources := SourceVerifier{Local: sourceReaderStub{value: record}, Snapshots: snapshotResolverStub{reader: snapshotStub{}}, Compatibility: compatibilityStub{}, Audit: auditPositionStub{value: auditPosition}, Clock: func() time.Time { return now }}
	verified, err := sources.Verify(context.Background(), SourceSelection{PointID: "point-a", SourceClass: "local", RepositoryClass: "standard", DeclaredRPOSeconds: 3600, TargetReleaseBuildID: "build-a", TargetToolVersion: "1.0.0", TargetSchemaVersion: "21"})
	if err != nil {
		t.Fatal(err)
	}
	continuity, err := (ContinuityResolver{}).Resolve(context.Background(), verified, nil)
	if err != nil {
		t.Fatal(err)
	}
	requirement := hostFenceRequirement(binding)
	reader, err := VerifyInstalledFenceEvidence(context.Background(), binding, []FenceRequirement{requirement}, installed, qualified, now)
	if err != nil {
		t.Fatal(err)
	}
	scope := AppliedFenceScope{ProfileID: requirement.ProfileID, ProfileVersion: requirement.ProfileVersion, PolicyID: requirement.PolicyID, PolicyVersion: requirement.PolicyVersion, ReleaseBuildID: requirement.ReleaseBuildID, EvaluatorVersion: requirement.EvaluatorVersion, FormerInstanceID: binding.FormerInstanceID, ReplacementInstanceID: binding.ReplacementInstanceID, RecoveryEpoch: binding.PriorEpoch, Boundaries: []AppliedFenceBoundary{{Boundary: requirement.Boundary, SubjectID: requirement.SubjectID, TargetID: requirement.TargetID, AdapterID: requirement.AdapterID, FormerIdentityID: requirement.FormerIdentityID}}}
	fences := FenceEvaluator{Scopes: fenceScopeFixture{scope: scope}, Evidence: reader, Clock: func() time.Time { return now }}
	fenceResult, err := fences.Verify(context.Background(), []FenceRequirement{requirement})
	if err != nil {
		t.Fatal(err)
	}
	auditDecision := generated.RestoreAuditDecision{Schema: generated.SchemaIDRestoreAuditDecision, SchemaVersion: "1.1.0", LocalLastEventID: 4, IndependentLastEventID: 4, IndependentCheckpointDigest: auditPosition.IndependentCheckpointDigest, Strategy: "matched", DecisionDigest: continuity.DecisionDigest}
	request := generated.RestoreRequest{Schema: generated.SchemaIDRestoreRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: 8, RecoveryEpoch: binding.PriorEpoch, TargetDigest: testCandidateDigest("2"), IdempotencyKey: "restore-plan-a", Source: verified.Binding, Fences: fenceResult.Items, AuditDecision: auditDecision, PointID: verified.Binding.PointID, DependencyIDs: []string{"binary-a"}, TargetIDs: []string{"control-a"}, PriorInstanceID: binding.FormerInstanceID, NewInstanceID: binding.ReplacementInstanceID, PriorRecoveryEpoch: binding.PriorEpoch, NextRecoveryEpoch: binding.PriorEpoch + 1, FenceSetDigest: fenceResult.FenceSetDigest, AuditDecisionDigest: continuity.DecisionDigest, CandidateDigest: testCandidateDigest("3")}
	restoreBinding := generated.RestoreBinding{Schema: generated.SchemaIDRestoreBinding, SchemaVersion: "1.1.0", Source: request.Source, PointID: request.PointID, DependencyIDs: request.DependencyIDs, TargetIDs: request.TargetIDs, TargetDigest: request.TargetDigest, PlanID: "plan-a", PlanDigest: testCandidateDigest("4"), HumanAcknowledgementID: "pending-human-acknowledgement", FenceSetDigest: request.FenceSetDigest, AuditDecisionDigest: request.AuditDecisionDigest, CandidateDigest: request.CandidateDigest, PriorInstanceID: request.PriorInstanceID, NewInstanceID: request.NewInstanceID, PriorRecoveryEpoch: request.PriorRecoveryEpoch, NextRecoveryEpoch: request.NextRecoveryEpoch, Status: "planned"}
	planner := &restorePlannerStub{qualification: RestoreQualification{Request: request, Binding: restoreBinding}}
	sessions := &restoreSessionsStub{}
	stager := &restoreStagerStub{}
	service, err := NewOperationsService(OperationsConfig{Sources: sources, Continuity: ContinuityResolver{}, Fences: fences, Plans: planner, Sessions: sessions, Candidates: stager, Canary: restoreCanaryStub{}, TargetReleaseBuildID: "build-a", TargetToolVersion: "1.0.0", TargetSchemaVersion: "21"})
	if err != nil {
		t.Fatal(err)
	}
	return service, request, planner, sessions, stager
}
