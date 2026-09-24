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

type restoreSessionsStub struct {
	transitions []string
	status      string
}

func (stub *restoreSessionsStub) CreateRestoreSession(context.Context, generated.RestoreBinding, store.RevisionToken) error {
	stub.transitions = append(stub.transitions, "session")
	return nil
}
func (stub *restoreSessionsStub) TransitionRestore(_ context.Context, _ generated.RestoreBinding, from, to, _ string, _ store.RevisionToken) error {
	stub.transitions = append(stub.transitions, from+">"+to)
	stub.status = to
	return nil
}
func (stub *restoreSessionsStub) RestoreStatus(context.Context, string) (generated.BrowserRestoreStatus, error) {
	return generated.BrowserRestoreStatus{}, nil
}
func (stub *restoreSessionsStub) ListRestoreStatuses(context.Context, string, int) ([]generated.BrowserRestoreStatus, store.RevisionToken, error) {
	return []generated.BrowserRestoreStatus{}, store.RevisionToken{}, nil
}
func (stub *restoreSessionsStub) RestoreExecutionStatus(context.Context, string) (string, error) {
	if stub.status != "" {
		return stub.status, nil
	}
	status := "planned"
	if len(stub.transitions) > 0 {
		last := stub.transitions[len(stub.transitions)-1]
		if last != "session" {
			for i := len(last) - 1; i >= 0; i-- {
				if last[i] == '>' {
					return last[i+1:], nil
				}
			}
		}
	}
	return status, nil
}

func TestOperationsRunResumesAfterRestoringWithoutRestaging(t *testing.T) {
	service, request, _, sessions, stager := operationsFixture(t)
	sessions.status = "restoring"
	binding := service.config.Plans.(*restorePlannerStub).qualification.Binding
	run := operationsRunRequest(request, binding, "ack-a")
	if _, err := service.Run(context.Background(), run, identity.Principal{ID: "human-a", Method: identity.LocalOSPeerMethod}); err != nil {
		t.Fatal(err)
	}
	if stager.calls != 0 || sessions.status != "verification-required" {
		t.Fatalf("restaged=%d status=%s", stager.calls, sessions.status)
	}
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
	run := operationsRunRequest(request, binding, "ack-a")
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

func TestOperationsRunRejectsExecutionIDWideningBeforeMutation(t *testing.T) {
	service, request, _, sessions, stager := operationsFixture(t)
	binding := service.config.Plans.(*restorePlannerStub).qualification.Binding
	run := operationsRunRequest(request, binding, "ack-a")
	run.RecoveryLeaseID = "other-lease"
	if _, err := service.Run(context.Background(), run, identity.Principal{ID: "human-a", Method: identity.LocalOSPeerMethod}); failureCode(err) != generated.ErrorCodePlanStale {
		t.Fatalf("widened execution binding err=%v", err)
	}
	if len(sessions.transitions) != 0 || stager.calls != 0 {
		t.Fatalf("mutation before execution binding validation: transitions=%v stages=%d", sessions.transitions, stager.calls)
	}
}

func TestOperationsRunRejectsPlaceholderAcknowledgementBeforeMutation(t *testing.T) {
	service, request, _, sessions, stager := operationsFixture(t)
	binding := service.config.Plans.(*restorePlannerStub).qualification.Binding
	run := operationsRunRequest(request, binding, "pending-human-acknowledgement")
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
	plannedFences, err := RequiredFenceSet([]FenceRequirement{requirement}, binding.SourceAdmissionDigest, binding.FenceQualificationDigest)
	if err != nil {
		t.Fatal(err)
	}
	auditDecision := generated.RestoreAuditDecision{Schema: generated.SchemaIDRestoreAuditDecision, SchemaVersion: "1.1.0", LocalLastEventID: 4, IndependentLastEventID: 4, IndependentCheckpointDigest: auditPosition.IndependentCheckpointDigest, Strategy: "matched", DecisionDigest: continuity.DecisionDigest}
	request := generated.RestoreRequest{Schema: generated.SchemaIDRestoreRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: 8, RecoveryEpoch: binding.PriorEpoch, TargetDigest: testCandidateDigest("2"), IdempotencyKey: "restore-plan-a", Source: verified.Binding, Fences: plannedFences.Items, AuditDecision: auditDecision, PointID: verified.Binding.PointID, DependencyIDs: []string{"binary-a"}, TargetIDs: []string{"control-a"}, PriorInstanceID: binding.FormerInstanceID, NewInstanceID: binding.ReplacementInstanceID, PriorRecoveryEpoch: binding.PriorEpoch, NextRecoveryEpoch: binding.PriorEpoch + 1, FenceSetDigest: plannedFences.FenceSetDigest, AuditDecisionDigest: continuity.DecisionDigest, CandidateDigest: testCandidateDigest("3"),
		FormerHostID: binding.FormerHostID, ReplacementHostID: binding.ReplacementHostID, RecoveryDraftID: binding.DraftID, CiphertextFingerprint: binding.CiphertextFingerprint, SourceAdmissionDigest: binding.SourceAdmissionDigest, FenceQualificationDigest: binding.FenceQualificationDigest, RecoveryRunID: binding.RunID, RecoveryStepID: binding.StepID, RecoveryLeaseID: binding.LeaseID, RecoveryChallengeID: binding.ChallengeID, RecoveryReceiptID: binding.ReceiptID}
	restoreBinding := generated.RestoreBinding{Schema: generated.SchemaIDRestoreBinding, SchemaVersion: "1.1.0", Source: request.Source, PointID: request.PointID, DependencyIDs: request.DependencyIDs, TargetIDs: request.TargetIDs, TargetDigest: request.TargetDigest, PlanID: "plan-a", PlanDigest: testCandidateDigest("4"), HumanAcknowledgementID: "pending-human-acknowledgement", FenceSetDigest: request.FenceSetDigest, AuditDecisionDigest: request.AuditDecisionDigest, CandidateDigest: request.CandidateDigest,
		FormerHostID: request.FormerHostID, ReplacementHostID: request.ReplacementHostID, RecoveryDraftID: request.RecoveryDraftID, CiphertextFingerprint: request.CiphertextFingerprint, SourceAdmissionDigest: request.SourceAdmissionDigest, FenceQualificationDigest: request.FenceQualificationDigest, RecoveryRunID: request.RecoveryRunID, RecoveryStepID: request.RecoveryStepID, RecoveryLeaseID: request.RecoveryLeaseID, RecoveryChallengeID: request.RecoveryChallengeID, RecoveryReceiptID: request.RecoveryReceiptID,
		PriorInstanceID: request.PriorInstanceID, NewInstanceID: request.NewInstanceID, PriorRecoveryEpoch: request.PriorRecoveryEpoch, NextRecoveryEpoch: request.NextRecoveryEpoch, Status: "planned"}
	planner := &restorePlannerStub{qualification: RestoreQualification{Request: request, Binding: restoreBinding}}
	sessions := &restoreSessionsStub{}
	stager := &restoreStagerStub{}
	service, err := NewOperationsService(OperationsConfig{Sources: sources, Continuity: ContinuityResolver{}, Fences: fences, Plans: planner, Sessions: sessions, Candidates: stager, Canary: restoreCanaryStub{}, TargetReleaseBuildID: "build-a", TargetToolVersion: "1.0.0", TargetSchemaVersion: "21"})
	if err != nil {
		t.Fatal(err)
	}
	return service, request, planner, sessions, stager
}

func operationsRunRequest(request generated.RestoreRequest, binding generated.RestoreBinding, acknowledgement string) generated.RestoreRunRequest {
	return generated.RestoreRunRequest{Schema: generated.SchemaIDRestoreRunRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: request.ExpectedStateRevision + 1, RecoveryEpoch: request.RecoveryEpoch, TargetDigest: binding.TargetDigest, IdempotencyKey: "restore-run-a", Source: binding.Source, PointID: binding.PointID, PlanID: binding.PlanID, PlanDigest: binding.PlanDigest, HumanAcknowledgementID: acknowledgement, FenceSetDigest: binding.FenceSetDigest, AuditDecisionDigest: binding.AuditDecisionDigest, CandidateDigest: binding.CandidateDigest, PriorInstanceID: binding.PriorInstanceID, NewInstanceID: binding.NewInstanceID, PriorRecoveryEpoch: binding.PriorRecoveryEpoch, NextRecoveryEpoch: binding.NextRecoveryEpoch,
		RecoveryRunID: binding.RecoveryRunID, RecoveryStepID: binding.RecoveryStepID, RecoveryLeaseID: binding.RecoveryLeaseID, RecoveryChallengeID: binding.RecoveryChallengeID, RecoveryReceiptID: binding.RecoveryReceiptID}
}
