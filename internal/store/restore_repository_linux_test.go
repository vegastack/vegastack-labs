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
	stored, err := repository.Get(context.Background(), binding.PlanID)
	if err != nil || stored.Status != "fenced" || stored.Binding.PlanDigest != session.Binding.PlanDigest {
		t.Fatalf("stored=%#v err=%v", stored, err)
	}
	if err := authority.PrepareRecoveredAuthority(context.Background(), binding, audit.Fingerprint(testDigest)); err != nil {
		t.Fatal(err)
	}
	verification, err := authority.VerifyAuditHistory(context.Background(), nil)
	if err != nil || verification.Status != "degraded" || verification.ReasonCode != "no-independent-anchor" {
		t.Fatalf("post-transition audit verification=%#v err=%v", verification, err)
	}
}

func testRestoreBinding(plan generated.Plan, instance, acknowledgement string) generated.RestoreBinding {
	source := generated.RestoreSourceBinding{Schema: generated.SchemaIDRestoreSourceBinding, SchemaVersion: "1.1.0", PointID: "point-a", PointDigest: testDigest, ManifestDigest: testDigest, VerificationDigest: testDigest, SourceClass: "local", RepositoryGenerationID: "generation-a", DeclaredRPOSeconds: 3600, CreatedAt: "2026-09-24T05:00:00Z", VerifiedAt: "2026-09-24T05:30:00Z", RecoveryEpoch: 0, DependencyDigests: []string{testDigest}}
	return generated.RestoreBinding{Schema: generated.SchemaIDRestoreBinding, SchemaVersion: "1.1.0", Source: source, PointID: source.PointID, DependencyIDs: []string{"dependency-a"}, TargetIDs: []string{"control-a"}, TargetDigest: plan.Binding.TargetDigest, PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, HumanAcknowledgementID: acknowledgement, FenceSetDigest: testDigest, AuditDecisionDigest: testDigest, CandidateDigest: testDigest, PriorInstanceID: instance, NewInstanceID: "instance-new-authority", PriorRecoveryEpoch: 0, NextRecoveryEpoch: 1, Status: "planned"}
}
