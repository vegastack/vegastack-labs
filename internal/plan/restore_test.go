package plan

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func TestRestorePlanPreservesExactFenceAuditAndAuthorityBinding(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	source := generated.RestoreSourceBinding{Schema: generated.SchemaIDRestoreSourceBinding, SchemaVersion: "1.1.0", PointID: "point-a", PointDigest: digest, ManifestDigest: digest, VerificationDigest: digest, SourceClass: "local", RepositoryGenerationID: "generation-a", KeyReferenceID: "key-a", DeclaredRPOSeconds: 3600, CreatedAt: "2026-09-24T05:00:00Z", VerifiedAt: "2026-09-24T05:30:00Z", RecoveryEpoch: 2, DependencyDigests: []string{digest}, RequiredDependencies: []generated.RestoreDependencyBinding{{DependencyID: "restic-binary", Kind: "binary", Digest: digest}}, TargetReleaseBuildID: "build-a", TargetToolVersion: "1.0.0", TargetSchemaVersion: "24"}
	fences := []generated.RestoreFenceItem{{Schema: generated.SchemaIDRestoreFenceItem, SchemaVersion: "1.1.0", Boundary: "host-service", SubjectID: "former-host", TargetID: "control-a", AdapterID: "adapter-a", FormerIdentityID: "former-identity", ProfileID: "labs", ProfileVersion: "1.0.0", PolicyID: "policy-a", PolicyVersion: "1.0.0", ReleaseBuildID: "build-a", EvaluatorVersion: "1.0.0", RecoveryEpoch: 2, RequiredEvidenceKinds: []string{"service-denied"}, Required: true, EvidenceIDs: []string{digest, "sha256:" + strings.Repeat("b", 64)}, EvidenceDigest: digest, Status: "required"}}
	decision := generated.RestoreAuditDecision{Schema: generated.SchemaIDRestoreAuditDecision, SchemaVersion: "1.1.0", LocalLastEventID: 4, IndependentLastEventID: 4, IndependentCheckpointDigest: digest, Strategy: "matched", DecisionDigest: digest}
	request := generated.RestoreRequest{Schema: generated.SchemaIDRestoreRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: 8, RecoveryEpoch: 2, TargetDigest: digest, IdempotencyKey: "restore-a", Source: source, Fences: fences, AuditDecision: decision, PointID: source.PointID, DependencyIDs: []string{"dependency-a"}, TargetIDs: []string{"control-a"}, PriorInstanceID: "instance-old", NewInstanceID: "instance-new", PriorRecoveryEpoch: 2, NextRecoveryEpoch: 3, FenceSetDigest: digest, AuditDecisionDigest: digest, CandidateDigest: digest,
		FormerHostID: "former-host", ReplacementHostID: "replacement-host", RecoveryDraftID: "draft-a", CiphertextFingerprint: digest, SourceAdmissionDigest: digest, FenceQualificationDigest: digest, RecoveryRunID: "run-a", RecoveryStepID: "step-a", RecoveryLeaseID: "lease-a", RecoveryChallengeID: "challenge-a", RecoveryReceiptID: "receipt-a"}
	request.CanaryRunID, request.CanaryStepID, request.CanaryLeaseID, request.CanaryChallengeID, request.CanaryReceiptID = "canary-run-a", "canary-step-a", "canary-lease-a", "canary-challenge-a", "canary-receipt-a"
	request.CanaryBindingDigest, _ = change.RestoreCanaryBindingDigest(request)
	declaration, err := change.BuildRestoreChange(context.Background(), request, source, fences, decision)
	if err != nil {
		t.Fatal(err)
	}
	result, binding, err := BuildRestorePlan(context.Background(), declaration, request, source, fences, decision)
	if err != nil {
		t.Fatal(err)
	}
	if risk, err := authorization.ClassifyPlan(result); err != nil || risk != authorization.RiskControlPlane {
		t.Fatalf("actual restore plan cannot enter human approval: risk=%s error=%v", risk, err)
	}
	repository := &fakePlanRepository{declaration: declaration, current: store.RevisionToken{StateRevision: result.Binding.StateRevision, RecoveryEpoch: result.Binding.RecoveryEpoch}}
	observations, err := NewStateObservationReader(repository)
	if err != nil {
		t.Fatal(err)
	}
	created, _ := time.Parse(time.RFC3339, result.CreatedAt)
	service := newTestService(t, repository, observations, func() time.Time { return created.Add(time.Second) })
	if err := service.ValidateCurrent(context.Background(), result); err != nil {
		t.Fatalf("actual restore plan rejected by ordinary approval freshness: %v", err)
	}
	changedSource := source
	changedSource.VerificationDigest = "sha256:" + strings.Repeat("b", 64)
	if _, _, err := BuildRestorePlan(context.Background(), declaration, request, changedSource, fences, decision); err == nil {
		t.Fatal("source verification substitution accepted")
	}
	if result.Status != "planned" || result.AuthorizationBranch != "human" || result.ExecutorMode != "central" || result.Risk != "control-plane" || len(result.Operations) != 2 || result.Operations[1].OperationType != "recovery.canary.noop" || result.Operations[1].OperationID != request.CanaryStepID || result.Operations[1].InputDigest != request.CanaryBindingDigest || binding.PlanID != result.PlanID || binding.PlanDigest != result.PlanDigest || binding.FenceSetDigest != request.FenceSetDigest || binding.AuditDecisionDigest != request.AuditDecisionDigest || binding.PriorInstanceID != request.PriorInstanceID || binding.NewInstanceID != request.NewInstanceID || binding.NextRecoveryEpoch != binding.PriorRecoveryEpoch+1 || binding.FormerHostID != request.FormerHostID || binding.RecoveryRunID != request.RecoveryRunID || binding.CanaryRunID != request.CanaryRunID || binding.SourceAdmissionDigest != request.SourceAdmissionDigest {
		t.Fatalf("plan=%#v binding=%#v", result, binding)
	}
}
