//go:build linux

package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestRestorePlanIsInertAndTransitionJournalIsAppendOnly(t *testing.T) {
	config := testConfig(t)
	config.Clock = func() time.Time { return time.Date(2026, 9, 24, 6, 0, 0, 0, time.UTC) }
	authority, err := Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = authority.Close() })
	before, err := authority.CurrentAuthority(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	draftRequest := validDeclarationStoreRequest()
	draftRequest.Document.DeclarationType = "recovery.restore"
	draftRequest.Document.Operations[0].OperationType = "recovery.restore.cutover"
	draftRequest.Document.Operations[0].AdapterID = "core.recovery"
	draftRequest.Document.Operations[0].Idempotent = false
	draftRequest.Document.ContentDigest = declarationContentDigest(draftRequest.Document, draftRequest.ReasonDigest)
	draft, err := NewDeclarationRepository(authority).CreateRevision(context.Background(), draftRequest)
	if err != nil {
		t.Fatal(err)
	}
	planRequest := validPlanStoreRequest(draft.Document)
	planRequest.Plan.Risk, planRequest.Plan.AuthorizationBranch = "control-plane", "human"
	planRequest.Plan.Operations[0].OperationType, planRequest.Plan.Operations[0].AdapterID, planRequest.Plan.Operations[0].Idempotent = "recovery.restore.cutover", "core.recovery", false
	planRequest.DesiredDeclaration.DeclarationType = "recovery.restore"
	planRequest.DesiredDeclaration.Operations = draft.Document.Operations
	planRequest.Plan.PlanID, planRequest.Plan.PlanDigest = "", ""
	preimage, _ := json.Marshal(planRequest.Plan)
	planSum := sha256.Sum256(preimage)
	planRequest.Plan.PlanDigest = "sha256:" + hex.EncodeToString(planSum[:])
	planRequest.Plan.PlanID = "plan-" + hex.EncodeToString(planSum[:16])
	planRequest.CanonicalBytes, _ = json.Marshal(planRequest.Plan)
	plannedBinding := testRestoreBinding(planRequest.Plan, before.InstanceID, "pending-human-acknowledgement")
	planRequest.RestoreQualification = &RestorePlanQualification{Request: testRestoreRequest(plannedBinding), Binding: plannedBinding}
	committed, err := NewPlanRepository(authority).CommitDeclarationAndPlan(context.Background(), planRequest)
	if err != nil {
		t.Fatal(err)
	}
	ackID := "ack-restore"
	if _, err := authority.conn.ExecContext(context.Background(), `INSERT INTO acknowledgement_requests(acknowledgement_id,plan_id,plan_digest,target_digest,reason_digest,human_id,authority_id,nonce_digest,state_revision,recovery_epoch,expires_at,status,request_bytes,pending_bytes,created_at,decided_at,consumed_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,'approved',?,?,?, ?,NULL)`, ackID, committed.Plan.PlanID, committed.Plan.PlanDigest, committed.Plan.Binding.TargetDigest, committed.Plan.Binding.ReasonDigest, "human-a", "authority-a", "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", committed.Plan.Binding.StateRevision, 0, committed.Plan.ExpiresAt, []byte(`{}`), []byte(`{}`), committed.Plan.CreatedAt, committed.Plan.CreatedAt); err != nil {
		t.Fatal(err)
	}
	binding := testRestoreBinding(committed.Plan, before.InstanceID, ackID)
	repository := NewRestoreRepository(authority)
	qualification, err := repository.Qualification(context.Background(), binding.PlanID)
	if err != nil || qualification.Binding.HumanAcknowledgementID != "pending-human-acknowledgement" || qualification.Request.CandidateDigest != binding.CandidateDigest {
		t.Fatalf("qualification=%#v err=%v", qualification, err)
	}
	session, err := repository.CreatePlan(context.Background(), RestorePlanRequest{Binding: binding, Expected: RevisionToken{StateRevision: committed.Plan.Binding.StateRevision, RecoveryEpoch: 0}})
	if err != nil {
		t.Fatal(err)
	}
	after, err := authority.CurrentAuthority(context.Background())
	if err != nil || after != before {
		t.Fatalf("planning changed authority: before=%#v after=%#v err=%v", before, after, err)
	}
	expected := RevisionToken{StateRevision: committed.Plan.Binding.StateRevision, RecoveryEpoch: 0}
	if err := repository.AppendTransition(context.Background(), RestoreTransitionRequest{PlanID: binding.PlanID, From: "planned", To: "fenced", PlanDigest: binding.PlanDigest, EvidenceDigest: testDigest, Expected: expected}); err != nil {
		t.Fatal(err)
	}
	if _, err := authority.conn.ExecContext(context.Background(), `UPDATE restore_transitions SET to_status='verified' WHERE plan_id=?`, binding.PlanID); err == nil {
		t.Fatal("transition history was mutable")
	}
	if err := repository.AppendTransition(context.Background(), RestoreTransitionRequest{PlanID: binding.PlanID, From: "fenced", To: "verified", PlanDigest: binding.PlanDigest, EvidenceDigest: testDigest, Expected: expected}); Code(err) != generated.ErrorCodeInputInvalid {
		t.Fatalf("skipped transition err = %v", err)
	}
	if err := repository.BindCandidate(context.Background(), RecoveryCandidateRequest{CandidateID: "candidate-a", PlanID: binding.PlanID, CandidateDigest: binding.CandidateDigest, PreservedAuthorityDigest: testDigest, FenceSetDigest: binding.FenceSetDigest, AuditDecisionDigest: binding.AuditDecisionDigest, DatabaseDigest: testDigest, JournalDigest: testDigest, BundleDigest: testDigest, Expected: expected}); err != nil {
		t.Fatal(err)
	}
	if _, found, err := repository.PendingPromotion(context.Background()); err != nil || found {
		t.Fatalf("fenced candidate was startup-promotable: found=%v err=%v", found, err)
	}
	if err := repository.AppendTransition(context.Background(), RestoreTransitionRequest{PlanID: binding.PlanID, From: "fenced", To: "restoring", PlanDigest: binding.PlanDigest, EvidenceDigest: testDigest, Expected: expected}); err != nil {
		t.Fatal(err)
	}
	if err := repository.AppendTransition(context.Background(), RestoreTransitionRequest{PlanID: binding.PlanID, From: "restoring", To: "verification-required", PlanDigest: binding.PlanDigest, EvidenceDigest: testDigest, Expected: expected}); err != nil {
		t.Fatal(err)
	}
	pending, found, err := repository.PendingPromotion(context.Background())
	if err != nil || !found || pending.Binding.PlanID != binding.PlanID || pending.DatabaseDigest != testDigest || pending.JournalDigest != testDigest {
		t.Fatalf("pending=%#v found=%v err=%v", pending, found, err)
	}
	stored, err := repository.Get(context.Background(), binding.PlanID)
	if err != nil || stored.Status != "verification-required" || stored.Binding.PlanDigest != session.Binding.PlanDigest {
		t.Fatalf("stored=%#v err=%v", stored, err)
	}
	if err := authority.PrepareRecoveredAuthority(context.Background(), binding, audit.Fingerprint(testDigest)); err != nil {
		t.Fatal(err)
	}
	bundleDigest, err := authority.WriteRecoveredAuthorityBundle(context.Background(), RecoveredAuthorityBundle{Plan: committed.Plan, Readable: committed.Readable, Request: qualification.Request, Binding: binding, Status: "verification-required"})
	if err != nil || !restoreDigest(bundleDigest) {
		t.Fatalf("bundle digest=%s err=%v", bundleDigest, err)
	}
	recovered, gotDigest, err := authority.RecoveredAuthorityBundle(context.Background(), binding.PlanID)
	if err != nil || gotDigest != bundleDigest || recovered.Status != "verification-required" || recovered.Binding.HumanAcknowledgementID != ackID {
		t.Fatalf("recovered=%#v digest=%s err=%v", recovered, gotDigest, err)
	}
	health, err := authority.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.EnableRecoveredAuthority(context.Background(), binding.NewInstanceID, binding.NextRecoveryEpoch, health.Revision.StateRevision, testDigest); err != nil {
		t.Fatal(err)
	}
	recovered, _, err = authority.RecoveredAuthorityBundle(context.Background(), binding.PlanID)
	if err != nil || recovered.Status != "verified" {
		t.Fatalf("verified recovered=%#v err=%v", recovered, err)
	}
	verification, err := authority.VerifyAuditHistory(context.Background(), nil)
	if err != nil || verification.Status != "degraded" || verification.ReasonCode != "no-independent-anchor" {
		t.Fatalf("post-transition audit verification=%#v err=%v", verification, err)
	}
}

func testRestoreRequest(binding generated.RestoreBinding) generated.RestoreRequest {
	fence := generated.RestoreFenceItem{Schema: generated.SchemaIDRestoreFenceItem, SchemaVersion: "1.1.0", Boundary: "host-service", SubjectID: "former-control", TargetID: "control-a", AdapterID: "adapter-a", FormerIdentityID: "former-identity", RequiredEvidenceKinds: []string{"service-denied"}, Required: true, EvidenceIDs: []string{binding.SourceAdmissionDigest, binding.FenceQualificationDigest}, EvidenceDigest: binding.FenceSetDigest, Status: "required"}
	decision := generated.RestoreAuditDecision{Schema: generated.SchemaIDRestoreAuditDecision, SchemaVersion: "1.1.0", LocalLastEventID: 0, IndependentLastEventID: 0, IndependentCheckpointDigest: binding.AuditDecisionDigest, Strategy: "matched", DecisionDigest: binding.AuditDecisionDigest}
	return generated.RestoreRequest{Schema: generated.SchemaIDRestoreRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: binding.PriorRecoveryEpoch, RecoveryEpoch: binding.PriorRecoveryEpoch, TargetDigest: binding.TargetDigest, IdempotencyKey: "restore-plan-test", Source: binding.Source, Fences: []generated.RestoreFenceItem{fence}, AuditDecision: decision, PointID: binding.PointID, DependencyIDs: binding.DependencyIDs, TargetIDs: binding.TargetIDs, PriorInstanceID: binding.PriorInstanceID, NewInstanceID: binding.NewInstanceID, PriorRecoveryEpoch: binding.PriorRecoveryEpoch, NextRecoveryEpoch: binding.NextRecoveryEpoch, FenceSetDigest: binding.FenceSetDigest, AuditDecisionDigest: binding.AuditDecisionDigest, CandidateDigest: binding.CandidateDigest,
		FormerHostID: binding.FormerHostID, ReplacementHostID: binding.ReplacementHostID, RecoveryDraftID: binding.RecoveryDraftID, CiphertextFingerprint: binding.CiphertextFingerprint, SourceAdmissionDigest: binding.SourceAdmissionDigest, FenceQualificationDigest: binding.FenceQualificationDigest, RecoveryRunID: binding.RecoveryRunID, RecoveryStepID: binding.RecoveryStepID, RecoveryLeaseID: binding.RecoveryLeaseID, RecoveryChallengeID: binding.RecoveryChallengeID, RecoveryReceiptID: binding.RecoveryReceiptID}
}

func testRestoreBinding(plan generated.Plan, instance, acknowledgement string) generated.RestoreBinding {
	source := generated.RestoreSourceBinding{Schema: generated.SchemaIDRestoreSourceBinding, SchemaVersion: "1.1.0", PointID: "point-a", PointDigest: testDigest, ManifestDigest: testDigest, VerificationDigest: testDigest, SourceClass: "local", RepositoryGenerationID: "generation-a", KeyReferenceID: "key-a", DeclaredRPOSeconds: 3600, CreatedAt: "2026-09-24T05:00:00Z", VerifiedAt: "2026-09-24T05:30:00Z", RecoveryEpoch: 0, DependencyDigests: []string{testDigest}, RequiredDependencies: []generated.RestoreDependencyBinding{{DependencyID: "restic-binary", Kind: "binary", Digest: testDigest}}, TargetReleaseBuildID: "build-a", TargetToolVersion: "1.0.0", TargetSchemaVersion: "24"}
	return generated.RestoreBinding{Schema: generated.SchemaIDRestoreBinding, SchemaVersion: "1.1.0", Source: source, PointID: source.PointID, DependencyIDs: []string{"dependency-a"}, TargetIDs: []string{"control-a"}, TargetDigest: plan.Binding.TargetDigest, PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, HumanAcknowledgementID: acknowledgement, FenceSetDigest: testDigest, AuditDecisionDigest: testDigest, CandidateDigest: testDigest,
		FormerHostID: "former-host", ReplacementHostID: "replacement-host", RecoveryDraftID: "draft-a", CiphertextFingerprint: testDigest, SourceAdmissionDigest: testDigest, FenceQualificationDigest: testDigest, RecoveryRunID: "run-a", RecoveryStepID: "step-a", RecoveryLeaseID: "lease-a", RecoveryChallengeID: "challenge-a", RecoveryReceiptID: "receipt-a",
		PriorInstanceID: instance, NewInstanceID: "instance-new-authority", PriorRecoveryEpoch: 0, NextRecoveryEpoch: 1, Status: "planned"}
}
