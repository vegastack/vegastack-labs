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
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

func TestScopedRestoreStatusListFiltersPartialGrantAndRejectsRevocation(t *testing.T) {
	ctx := context.Background()
	authority := openTestStore(t)
	current, err := authority.CurrentAuthority(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.conn.ExecContext(ctx, `UPDATE system_meta SET state_revision=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	for _, suffix := range []string{"a", "b"} {
		planID := "restore-plan-" + suffix
		planDigest := string(digestForText(planID))
		declarationID := "restore-declaration-" + suffix
		acknowledgementID := "restore-ack-" + suffix
		binding := testRestoreBinding(generated.Plan{PlanID: planID, PlanDigest: planDigest, Binding: generated.PlanBinding{TargetDigest: string(digestForText("restore-target-" + suffix))}}, current.InstanceID, acknowledgementID)
		binding.PointID = "restore-point-" + suffix
		binding.Source.PointID = binding.PointID
		binding.NewInstanceID = "restore-instance-" + suffix
		binding.FormerHostID = "restore-former-host-" + suffix
		binding.ReplacementHostID = "restore-replacement-host-" + suffix
		binding.RecoveryDraftID = "restore-draft-" + suffix
		binding.CanaryRunID = "restore-canary-run-" + suffix
		binding.CanaryStepID = "restore-canary-step-" + suffix
		binding.CanaryLeaseID = "restore-canary-lease-" + suffix
		binding.CanaryChallengeID = "restore-canary-challenge-" + suffix
		binding.CanaryReceiptID = "restore-canary-receipt-" + suffix
		binding.CanaryBindingDigest = string(digestForText("restore-canary-binding-" + suffix))
		binding.PlanID = planID
		binding.PlanDigest = planDigest
		binding.HumanAcknowledgementID = acknowledgementID
		rawBinding, err := json.Marshal(binding)
		if err != nil {
			t.Fatal(err)
		}
		if err := generated.ValidateContractJSON(generated.SchemaIDRestoreBinding, rawBinding, generated.ContractExact); err != nil {
			t.Fatalf("restore binding %s: %v", suffix, err)
		}

		if _, err := authority.conn.ExecContext(ctx, `INSERT INTO declaration_revisions(declaration_id,declaration_revision,declaration_type,state_revision,recovery_epoch,content_digest,reason_digest,status,canonical_bytes,created_at,created_by,agent_session_id) VALUES(?,1,'recovery.restore',1,0,?,?,'committed',X'7B7D','2026-09-24T06:00:00Z','human-a','session-a')`, declarationID, digestForText("content-"+suffix), digestForText("reason-"+suffix)); err != nil {
			t.Fatal(err)
		}
		if _, err := authority.conn.ExecContext(ctx, `INSERT INTO immutable_plans(plan_id,plan_digest,declaration_id,declaration_revision,state_revision,recovery_epoch,observation_fingerprint,idempotency_key_digest,request_digest,canonical_bytes,readable_plan,readable_digest,created_at,expires_at) VALUES(?,?,?,1,1,0,?,?,?,?,?,?,?,?)`, planID, planDigest, declarationID, digestForText("observation-"+suffix), digestForText("idempotency-"+suffix), digestForText("request-"+suffix), []byte(`{}`), "restore plan", digestForText("readable-"+suffix), "2026-09-24T06:00:00Z", "2026-09-24T07:00:00Z"); err != nil {
			t.Fatal(err)
		}
		if _, err := authority.conn.ExecContext(ctx, `INSERT INTO acknowledgement_requests(acknowledgement_id,plan_id,plan_digest,target_digest,reason_digest,human_id,authority_id,nonce_digest,state_revision,recovery_epoch,expires_at,status,request_bytes,pending_bytes,created_at,decided_at,consumed_at) VALUES(?,?,?,?,?,'human-a','authority-a',?,1,0,'2026-09-24T07:00:00Z','approved',X'7B7D',X'7B7D','2026-09-24T06:00:00Z','2026-09-24T06:00:00Z',NULL)`, acknowledgementID, planID, planDigest, binding.TargetDigest, digestForText("ack-reason-"+suffix), digestForText("nonce-"+suffix)); err != nil {
			t.Fatal(err)
		}
		if _, err := authority.conn.ExecContext(ctx, `INSERT INTO restore_sessions(plan_id,plan_digest,declaration_id,declaration_revision,human_acknowledgement_id,point_id,point_digest,dependency_digest,fence_set_digest,audit_decision_digest,target_digest,candidate_digest,prior_instance_id,new_instance_id,prior_recovery_epoch,next_recovery_epoch,state_revision,binding_bytes,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, binding.PlanID, binding.PlanDigest, declarationID, 1, binding.HumanAcknowledgementID, binding.PointID, binding.Source.PointDigest, restoreDependencyDigest(binding.Source.DependencyDigests), binding.FenceSetDigest, binding.AuditDecisionDigest, binding.TargetDigest, binding.CandidateDigest, binding.PriorInstanceID, binding.NewInstanceID, binding.PriorRecoveryEpoch, binding.NextRecoveryEpoch, 1, rawBinding, "2026-09-24T06:00:00Z"); err != nil {
			t.Fatal(err)
		}
	}

	seedReadGrant(t, authority, "restore-reader", "restore.read", "restore-plan", "restore-plan-b", 4, "active")
	scope, err := NewReadAuthorizer(authority).AuthorizeRead(ctx, identity.Principal{ID: "restore-reader", Method: identity.LocalOSPeerMethod}, authorization.ReadTarget{Capability: "restore.read", ResourceKind: "restore-plan"})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := NewPlanRepository(authority).CurrentRevision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	items, _, err := NewRestoreRepository(authority).ListRestoreStatusesScoped(ctx, scope, snapshot, "", 10)
	if err != nil || len(items) != 1 || items[0].PlanID != "restore-plan-b" {
		t.Fatalf("items=%#v err=%v", items, err)
	}
	if _, err := authority.conn.ExecContext(ctx, `UPDATE read_grants SET status='revoked' WHERE principal_id='restore-reader'`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := NewRestoreRepository(authority).ListRestoreStatusesScoped(ctx, scope, snapshot, "", 10); Code(err) != generated.ErrorCodeAuthorizationDenied {
		t.Fatalf("revoked scope err=%v", err)
	}
}

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
	draftRequest.Document.Operations[0].OperationID = "step-a"
	draftRequest.Document.Operations[0].TargetID = "control-a"
	draftRequest.Document.Operations[0].Idempotent = false
	draftRequest.Document.Operations = append(draftRequest.Document.Operations, generated.DeclarationOperation{Sequence: 2, OperationID: "canary-step-a", OperationType: "recovery.canary.noop", AdapterID: "core.recovery", TargetID: "instance-new-authority", InputDigest: testDigest, ArtifactDigest: testDigest, Idempotent: true})
	draftRequest.Document.ContentDigest = declarationContentDigest(draftRequest.Document, draftRequest.ReasonDigest)
	draft, err := NewDeclarationRepository(authority).CreateRevision(context.Background(), draftRequest)
	if err != nil {
		t.Fatal(err)
	}
	planRequest := validPlanStoreRequest(draft.Document)
	planRequest.Plan.Risk, planRequest.Plan.AuthorizationBranch = "control-plane", "human"
	planRequest.Plan.Operations = []generated.PlanOperation{
		{Sequence: 1, OperationID: "step-a", OperationType: "recovery.restore.cutover", AdapterID: "core.recovery", ExecutorID: "executor-central", TargetID: "control-a", InputDigest: testDigest, ArtifactDigest: testDigest, Idempotent: false},
		{Sequence: 2, OperationID: "canary-step-a", OperationType: "recovery.canary.noop", AdapterID: "core.recovery", ExecutorID: "executor-central", TargetID: "instance-new-authority", InputDigest: testDigest, ArtifactDigest: testDigest, Idempotent: true},
	}
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
	requestBytes, _ := json.Marshal(planRequest.RestoreQualification.Request)
	if err := generated.ValidateContractJSON(generated.SchemaIDRestoreRequest, requestBytes, generated.ContractExact); err != nil {
		t.Fatalf("restore request fixture: %v", err)
	}
	bindingBytes, _ := json.Marshal(planRequest.RestoreQualification.Binding)
	if err := generated.ValidateContractJSON(generated.SchemaIDRestoreBinding, bindingBytes, generated.ContractExact); err != nil {
		t.Fatalf("restore binding fixture: %v", err)
	}
	if !validRestorePlanQualification(*planRequest.RestoreQualification, planRequest.Plan) {
		t.Fatal("restore qualification fixture does not match its plan")
	}
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
	if err := authority.VerifyRecoveryOldEpochMutationDenied(context.Background(), health.Revision.StateRevision, binding.PriorRecoveryEpoch); err != nil {
		t.Fatalf("former epoch reached mutation callback: %v", err)
	}
	human := "human-a"
	if err := authority.RecordRecoveryCanaryNoop(context.Background(), RecoveryCanaryNoopRequest{PlanID: binding.PlanID, PlanDigest: binding.PlanDigest, RunID: binding.CanaryRunID, StepID: binding.CanaryStepID, LeaseID: binding.CanaryLeaseID, InstanceID: binding.NewInstanceID, ResultDigest: testDigest, RecoveryEpoch: binding.NextRecoveryEpoch, StateRevision: health.Revision.StateRevision, Attribution: audit.Attribution{AuthenticatedPrincipalID: human, AuthenticatedPrincipalMethod: "local-os-peer", ResponsibleHumanPrincipalID: &human}}); err != nil {
		t.Fatal(err)
	}
	eventID, eventAt, err := authority.RecoveryCanaryNoopEvent(context.Background(), binding.PlanID, binding.CanaryRunID)
	if err != nil || eventID < 1 || !eventAt.Equal(config.Clock()) {
		t.Fatalf("canary noop event=%d at=%s err=%v", eventID, eventAt, err)
	}
	chain, err := authority.ChainRange(context.Background(), audit.EventID(eventID), audit.EventID(eventID))
	if err != nil {
		t.Fatal(err)
	}
	signature, publicKey, receipt, independent := testDigest, "checkpoint-key-a", testDigest, testDigest
	verified := eventAt.UTC().Format(time.RFC3339)
	payload := []byte("encrypted-recovery-canary-checkpoint")
	payloadSum := sha256.Sum256(payload)
	checkpoint := generated.AuditCheckpoint{Schema: generated.SchemaIDAuditCheckpoint, SchemaVersion: "1.1.0", CheckpointID: "checkpoint-recovery-canary", FirstEventID: eventID, LastEventID: eventID, ChainDigest: string(chain.RangeDigest), InstanceID: binding.NewInstanceID, FirstSegmentSequence: chain.Links[0].SegmentSequence, LastSegmentSequence: chain.Links[0].SegmentSequence, SignerReferenceID: "signer-recovery-canary", SignerMaterialVersion: "version-recovery-canary", SignatureDigest: &signature, PublicKeyID: &publicKey, ExportReceiptDigest: &receipt, IndependentReadDigest: &independent, IndependentCopyDigest: &independent, Status: "anchored", ReasonCode: "independent-match", SourceKind: "independent", ProofClass: "live", VerifiedAt: &verified, VerificationStatus: "verified", RecoveryEpoch: binding.NextRecoveryEpoch}
	mutation := RecoveryCanaryMutationRequest{PlanID: binding.PlanID, PlanDigest: binding.PlanDigest, RunID: binding.CanaryRunID, StepID: binding.CanaryStepID, LeaseID: binding.CanaryLeaseID, InstanceID: binding.NewInstanceID, StateRevision: health.Revision.StateRevision, RecoveryEpoch: binding.NextRecoveryEpoch}
	for name, mutateRecord := range map[string]func(*RecoveryCanaryCheckpointRecord){
		"future inner timestamp": func(record *RecoveryCanaryCheckpointRecord) {
			stamp := eventAt.Add(time.Second).Format(time.RFC3339)
			record.Checkpoint.VerifiedAt = &stamp
		},
		"future outer timestamp": func(record *RecoveryCanaryCheckpointRecord) {
			record.CapabilityObservedAt = eventAt.Add(time.Second)
		},
	} {
		t.Run(name, func(t *testing.T) {
			record := RecoveryCanaryCheckpointRecord{Checkpoint: checkpoint, ExactPath: "audit-anchor/checkpoint-recovery-canary.json.enc", EncryptedPayload: payload, PayloadDigest: "sha256:" + hex.EncodeToString(payloadSum[:]), CapabilityObservedAt: eventAt}
			mutateRecord(&record)
			err := authority.WithRecoveryCanaryMutation(context.Background(), mutation, func(scoped context.Context) error {
				return authority.RecordRecoveryCanaryCheckpoint(scoped, mutation, eventAt, record)
			})
			if Code(err) != generated.ErrorCodeIntegrityFailure {
				t.Fatalf("timestamp accepted: %v", err)
			}
		})
	}
	err = authority.WithRecoveryCanaryMutation(context.Background(), mutation, func(scoped context.Context) error {
		return authority.RecordRecoveryCanaryCheckpoint(scoped, mutation, eventAt, RecoveryCanaryCheckpointRecord{Checkpoint: checkpoint, ExactPath: "audit-anchor/checkpoint-recovery-canary.json.enc", EncryptedPayload: payload, PayloadDigest: "sha256:" + hex.EncodeToString(payloadSum[:]), CapabilityObservedAt: eventAt})
	})
	if err != nil {
		t.Fatal(err)
	}
	createdCheckpoint, err := authority.GetAuditCheckpoint(context.Background(), checkpoint.CheckpointID)
	if err != nil || createdCheckpoint.CheckpointID != checkpoint.CheckpointID || createdCheckpoint.Status != "anchored" || createdCheckpoint.LastEventID != eventID {
		t.Fatalf("checkpoint=%#v err=%v", createdCheckpoint, err)
	}
	if err := authority.EnableRecoveredAuthority(context.Background(), binding.NewInstanceID, binding.NextRecoveryEpoch, health.Revision.StateRevision, testDigest); err != nil {
		t.Fatal(err)
	}
	recovered, _, err = authority.RecoveredAuthorityBundle(context.Background(), binding.PlanID)
	if err != nil || recovered.Status != "verified" {
		t.Fatalf("verified recovered=%#v err=%v", recovered, err)
	}
	verification, err := authority.VerifyAuditHistory(context.Background(), nil)
	if err != nil || verification.Status != "anchored" || verification.ReasonCode != "local-anchor-valid" || verification.InstanceID != binding.NewInstanceID || verification.RecoveryEpoch != binding.NextRecoveryEpoch || verification.LastAnchoredSequence != checkpoint.LastSegmentSequence+1 {
		t.Fatalf("post-transition audit verification=%#v err=%v", verification, err)
	}
}

func testRestoreRequest(binding generated.RestoreBinding) generated.RestoreRequest {
	fence := generated.RestoreFenceItem{Schema: generated.SchemaIDRestoreFenceItem, SchemaVersion: "1.1.0", Boundary: "host-service", SubjectID: "former-control", TargetID: "control-a", AdapterID: "adapter-a", FormerIdentityID: "former-identity",
		ProfileID: "vegastack-labs", ProfileVersion: "1.0.0", PolicyID: "recovery-policy", PolicyVersion: "1.0.0", ReleaseBuildID: "build-a", EvaluatorVersion: "1.0.0", RecoveryEpoch: binding.PriorRecoveryEpoch,
		RequiredEvidenceKinds: []string{"service-denied"}, Required: true, EvidenceIDs: []string{binding.SourceAdmissionDigest, binding.FenceQualificationDigest}, EvidenceDigest: binding.FenceSetDigest, Status: "required"}
	decision := generated.RestoreAuditDecision{Schema: generated.SchemaIDRestoreAuditDecision, SchemaVersion: "1.1.0", LocalLastEventID: 0, IndependentLastEventID: 0, IndependentCheckpointDigest: binding.AuditDecisionDigest, Strategy: "matched", DecisionDigest: binding.AuditDecisionDigest}
	return generated.RestoreRequest{Schema: generated.SchemaIDRestoreRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: binding.PriorRecoveryEpoch, RecoveryEpoch: binding.PriorRecoveryEpoch, TargetDigest: binding.TargetDigest, IdempotencyKey: "restore-plan-test", Source: binding.Source, Fences: []generated.RestoreFenceItem{fence}, AuditDecision: decision, PointID: binding.PointID, DependencyIDs: binding.DependencyIDs, TargetIDs: binding.TargetIDs, PriorInstanceID: binding.PriorInstanceID, NewInstanceID: binding.NewInstanceID, PriorRecoveryEpoch: binding.PriorRecoveryEpoch, NextRecoveryEpoch: binding.NextRecoveryEpoch, FenceSetDigest: binding.FenceSetDigest, AuditDecisionDigest: binding.AuditDecisionDigest, CandidateDigest: binding.CandidateDigest,
		FormerHostID: binding.FormerHostID, ReplacementHostID: binding.ReplacementHostID, RecoveryDraftID: binding.RecoveryDraftID, CiphertextFingerprint: binding.CiphertextFingerprint, SourceAdmissionDigest: binding.SourceAdmissionDigest, FenceQualificationDigest: binding.FenceQualificationDigest, RecoveryRunID: binding.RecoveryRunID, RecoveryStepID: binding.RecoveryStepID, RecoveryLeaseID: binding.RecoveryLeaseID, RecoveryChallengeID: binding.RecoveryChallengeID, RecoveryReceiptID: binding.RecoveryReceiptID, CanaryRunID: binding.CanaryRunID, CanaryStepID: binding.CanaryStepID, CanaryLeaseID: binding.CanaryLeaseID, CanaryChallengeID: binding.CanaryChallengeID, CanaryReceiptID: binding.CanaryReceiptID, CanaryBindingDigest: binding.CanaryBindingDigest}
}

func testRestoreBinding(plan generated.Plan, instance, acknowledgement string) generated.RestoreBinding {
	source := generated.RestoreSourceBinding{Schema: generated.SchemaIDRestoreSourceBinding, SchemaVersion: "1.1.0", PointID: "point-a", PointDigest: testDigest, ManifestDigest: testDigest, VerificationDigest: testDigest, SourceClass: "local", RepositoryGenerationID: "generation-a", KeyReferenceID: "key-a", DeclaredRPOSeconds: 3600, CreatedAt: "2026-09-24T05:00:00Z", VerifiedAt: "2026-09-24T05:30:00Z", RecoveryEpoch: 0, DependencyDigests: []string{testDigest}, RequiredDependencies: []generated.RestoreDependencyBinding{{DependencyID: "restic-binary", Kind: "binary", Digest: testDigest}}, TargetReleaseBuildID: "build-a", TargetToolVersion: "1.0.0", TargetSchemaVersion: "26"}
	return generated.RestoreBinding{Schema: generated.SchemaIDRestoreBinding, SchemaVersion: "1.1.0", Source: source, PointID: source.PointID, DependencyIDs: []string{"dependency-a"}, TargetIDs: []string{"control-a"}, TargetDigest: plan.Binding.TargetDigest, PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, HumanAcknowledgementID: acknowledgement, FenceSetDigest: testDigest, AuditDecisionDigest: testDigest, CandidateDigest: testDigest,
		FormerHostID: "former-host", ReplacementHostID: "replacement-host", RecoveryDraftID: "draft-a", CiphertextFingerprint: testDigest, SourceAdmissionDigest: string(digestForText("source-admission")), FenceQualificationDigest: string(digestForText("fence-qualification")), RecoveryRunID: "run-a", RecoveryStepID: "step-a", RecoveryLeaseID: "lease-a", RecoveryChallengeID: "challenge-a", RecoveryReceiptID: "receipt-a",
		CanaryRunID: "canary-run-a", CanaryStepID: "canary-step-a", CanaryLeaseID: "canary-lease-a", CanaryChallengeID: "canary-challenge-a", CanaryReceiptID: "canary-receipt-a", CanaryBindingDigest: testDigest,
		PriorInstanceID: instance, NewInstanceID: "instance-new-authority", PriorRecoveryEpoch: 0, NextRecoveryEpoch: 1, Status: "planned"}
}
