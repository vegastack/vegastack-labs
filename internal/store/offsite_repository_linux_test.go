//go:build linux

package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestOffsiteRunSpecIsAppendedByDeclarationPlanCommit(t *testing.T) {
	ctx := context.Background()
	backups, point, revision := seededVerificationPoint(t)
	// Advance control-plane state independently of the already-created backup
	// point so this regression proves the two revision domains stay distinct.
	if _, err := backups.store.conn.ExecContext(ctx, `UPDATE system_meta SET state_revision=state_revision+1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	revision.StateRevision++
	digest := "sha256:" + strings.Repeat("a", 64)
	draftRequest := validDeclarationStoreRequest()
	draftRequest.Document.DeclarationID = "declaration-offsite-a"
	draftRequest.Document.DeclarationType = "backup.offsite"
	draftRequest.Document.StateRevision = revision.StateRevision + 1
	draftRequest.Document.RecoveryEpoch = revision.RecoveryEpoch
	draftRequest.Document.Operations = []generated.DeclarationOperation{{Sequence: 1, OperationID: "operation-offsite-a", OperationType: "backup.offsite.copy", AdapterID: "labs.r2-offsite", TargetID: "generation-plan-a", InputDigest: digest, ArtifactDigest: digest, Idempotent: false,
		OffsiteRunSpec: &generated.OffsiteRunSpec{GenerationID: "generation-plan-a", SourcePointID: point.PointID, SourceRevision: point.SourceRevision, SnapshotPath: "/var/lib/vsk-labs/offsite/source-a", RepositoryURL: "s3:https://account.r2.cloudflarestorage.com/bucket-a/critical/generation-plan-a", ParentReferenceID: "parent-a", RepositoryKeyReferenceID: "password-a", ObserverReferenceID: "observer-a", RuleDigest: digest, G008EvidenceDigest: digest, MaximumBytes: 4096, MaximumPUTs: 100, MaximumLISTs: 20, MaximumRetainedGenerations: 100, RuleLimit: 1000, RetentionSeconds: 86400, SessionTTLSeconds: 60}}}
	draftRequest.Expected = revision
	draftRequest.KeyDigest, draftRequest.RequestDigest = "sha256:"+strings.Repeat("b", 64), "sha256:"+strings.Repeat("b", 64)
	draftRequest.Document.ContentDigest = declarationContentDigest(draftRequest.Document, draftRequest.ReasonDigest)
	draft, err := NewDeclarationRepository(backups.store).CreateRevision(ctx, draftRequest)
	if err != nil {
		t.Fatal(err)
	}

	planRequest := validPlanStoreRequest(draft.Document)
	planRequest.DesiredDeclaration.StateRevision = draft.Document.StateRevision + 1
	planRequest.Plan.Binding.PriorStateRevision = draft.Document.StateRevision
	planRequest.Plan.Binding.StateRevision = draft.Document.StateRevision + 1
	planRequest.Plan.Binding.RecoveryEpoch = revision.RecoveryEpoch
	planRequest.Plan.Binding.DeclarationRevision = planRequest.DesiredDeclaration.Revision
	planRequest.Plan.Operations = []generated.PlanOperation{{Sequence: 1, OperationID: "operation-offsite-a", OperationType: "backup.offsite.copy", AdapterID: "labs.r2-offsite", ExecutorID: "executor-central", TargetID: "generation-plan-a", InputDigest: digest, ArtifactDigest: digest, Idempotent: false}}
	planRequest.Expected = RevisionToken{StateRevision: draft.Document.StateRevision, RecoveryEpoch: revision.RecoveryEpoch}
	planRequest.KeyDigest, planRequest.RequestDigest = "sha256:"+strings.Repeat("c", 64), "sha256:"+strings.Repeat("c", 64)
	planRequest.Plan.PlanID, planRequest.Plan.PlanDigest = "", ""
	preimage, _ := json.Marshal(planRequest.Plan)
	planSum := sha256.Sum256(preimage)
	planRequest.Plan.PlanDigest = "sha256:" + hex.EncodeToString(planSum[:])
	planRequest.Plan.PlanID = "plan-" + hex.EncodeToString(planSum[:16])
	planRequest.CanonicalBytes, _ = json.Marshal(planRequest.Plan)
	if _, err := NewPlanRepository(backups.store).CommitDeclarationAndPlan(ctx, planRequest); err != nil {
		t.Fatal(err)
	}
	stored, err := NewOffsiteRepository(backups.store).RunSpec(ctx, "generation-plan-a")
	if err != nil || stored.SourcePointID != point.PointID || stored.SourceRevision != point.SourceRevision || stored.RepositoryKeyReferenceID != "password-a" || stored.StateRevision != planRequest.Plan.Binding.StateRevision || stored.SourceRevision == stored.StateRevision {
		t.Fatalf("production run spec = %#v, %v", stored, err)
	}
	created := backups.store.config.Clock().UTC().Truncate(time.Second)
	maximum := created.Add(time.Hour)
	for index, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO plan_runs(run_id,plan_id,plan_digest,authorization_decision_id,policy_version,executor_mode,executor_id,executor_binding_digest,status,cancellation_requested,rollback_status,verification_status,changed,state_revision,recovery_epoch,submit_key_digest,request_digest,canonical_bytes,created_at,updated_at) VALUES('run-offsite-a',?,?,'decision-a','1.0.0','central','executor-central',?,'running',0,'not-requested','pending',0,?,?,?, ?,X'7B7D',?,?)`, []any{planRequest.Plan.PlanID, planRequest.Plan.PlanDigest, digest, stored.StateRevision, stored.RecoveryEpoch, digest, digest, created.Format(time.RFC3339), created.Format(time.RFC3339)}},
		{`INSERT INTO plan_run_steps(step_id,run_id,sequence,operation_id,operation_type,adapter_id,executor_id,target_id,input_digest,artifact_digest,idempotent,status,effect_state,active_lease_id,started_at) VALUES('step-offsite-a','run-offsite-a',1,'operation-offsite-a','backup.offsite.copy','labs.r2-offsite','executor-central','generation-plan-a',?,?,0,'running','intent-recorded','lease-offsite-a',?)`, []any{digest, digest, created.Format(time.RFC3339)}},
		{`INSERT INTO target_execution_leases(lease_id,run_id,step_id,target_id,binding_digest,nonce_digest,recovery_epoch,claimed_at,renew_after,expires_at,maximum_expires_at,status,canonical_bytes) VALUES('lease-offsite-a','run-offsite-a','step-offsite-a','generation-plan-a',?,?,?, ?,?,?,?,'active',X'7B7D')`, []any{digest, digest, stored.RecoveryEpoch, created.Format(time.RFC3339), created.Format(time.RFC3339), maximum.Format(time.RFC3339), maximum.Format(time.RFC3339)}},
	} {
		if _, err := backups.store.conn.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatalf("seed offsite custody statement %d: %v", index, err)
		}
	}
	binding := OffsiteCustodyBinding{PlanID: planRequest.Plan.PlanID, PlanDigest: planRequest.Plan.PlanDigest, RunID: "run-offsite-a", StepID: "step-offsite-a", LeaseID: "lease-offsite-a", GenerationID: stored.GenerationID, SourcePointID: stored.SourcePointID, SourceRevision: stored.SourceRevision, StateRevision: stored.StateRevision, RecoveryEpoch: stored.RecoveryEpoch, MaximumExpiresAt: maximum}
	if err := NewOffsiteRepository(backups.store).BindCustodyLease(ctx, binding); err != nil {
		t.Fatal(err)
	}
	binding.SourceRevision++
	if err := NewOffsiteRepository(backups.store).VerifyCustodyLease(ctx, binding, created); err == nil {
		t.Fatal("custody lease accepted mismatched source revision")
	}
	binding.SourceRevision = stored.SourceRevision
	cleanup := OffsiteCleanupObligation{ObligationID: "cleanup-generation-plan-a", GenerationID: stored.GenerationID, ObjectKey: "critical/generation-plan-a/locks/cutoff-a",
		CredentialReferenceID: stored.ParentReferenceID, CredentialFingerprint: digest, PlanID: binding.PlanID, PlanDigest: binding.PlanDigest, RunID: binding.RunID, StepID: binding.StepID, LeaseID: binding.LeaseID,
		SourceRevision: binding.SourceRevision, StateRevision: binding.StateRevision, RecoveryEpoch: binding.RecoveryEpoch}
	if err := NewOffsiteRepository(backups.store).AppendCleanupObligation(ctx, cleanup); err != nil {
		t.Fatal(err)
	}
	receipted := cleanup
	receipted.ObligationID = "cleanup-generation-plan-b"
	receipted.ObjectKey = "critical/generation-plan-a/locks/cutoff-b"
	if err := NewOffsiteRepository(backups.store).AppendCleanupObligation(ctx, receipted); err != nil {
		t.Fatal(err)
	}
	if err := NewOffsiteRepository(backups.store).AppendCleanupUploadReceipt(ctx, receipted.ObligationID, "upload-b"); err != nil {
		t.Fatal(err)
	}
	pending, err := NewOffsiteRepository(backups.store).PendingCleanupObligations(ctx, cleanup.CredentialReferenceID, cleanup.CredentialFingerprint, cleanup.RecoveryEpoch)
	if err != nil || len(pending) != 2 || len(pending[0].UploadIDs) != 0 || len(pending[1].UploadIDs) != 1 || pending[1].UploadIDs[0] != "upload-b" {
		t.Fatalf("pending cleanup before restart = %#v, %v", pending, err)
	}
	config := backups.store.config
	if err := backups.store.Close(); err != nil {
		t.Fatal(err)
	}
	config.Mode = OpenExisting
	reopened, err := Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	restarted := NewOffsiteRepository(reopened)
	pending, err = restarted.PendingCleanupObligations(ctx, cleanup.CredentialReferenceID, cleanup.CredentialFingerprint, cleanup.RecoveryEpoch)
	if err != nil || len(pending) != 2 || pending[0].ObjectKey != cleanup.ObjectKey || len(pending[0].UploadIDs) != 0 || len(pending[1].UploadIDs) != 1 || pending[1].UploadIDs[0] != "upload-b" {
		t.Fatalf("pending cleanup after restart = %#v, %v", pending, err)
	}
	if err := restarted.ResolveCleanupObligation(ctx, cleanup.ObligationID); err != nil {
		t.Fatal(err)
	}
	if err := restarted.ResolveCleanupObligation(ctx, receipted.ObligationID); err != nil {
		t.Fatal(err)
	}
	if pending, err = restarted.PendingCleanupObligations(ctx, cleanup.CredentialReferenceID, cleanup.CredentialFingerprint, cleanup.RecoveryEpoch); err != nil || len(pending) != 0 {
		t.Fatalf("resolved cleanup remained pending = %#v, %v", pending, err)
	}
}

func TestOffsiteRepositoryPersistsAppendOnlyReceiptsAndCASLastGood(t *testing.T) {
	ctx := context.Background()
	backupRepository, point, revision := seededVerificationPoint(t)
	repository := NewOffsiteRepository(backupRepository.store)
	now := time.Now().UTC().Truncate(time.Second)
	runSpec := OffsiteRunSpecRecord{GenerationID: "generation-a", SourcePointID: point.PointID, SnapshotPath: "/var/lib/vsk-labs/offsite/source-a", RepositoryURL: "s3:https://account.r2.cloudflarestorage.com/bucket-a/critical/generation-a", ParentReferenceID: "parent-a", RepositoryKeyReferenceID: "password-a", ObserverReferenceID: "observer-a",
		RuleDigest: "sha256:" + strings.Repeat("c", 64), G008EvidenceDigest: "sha256:" + strings.Repeat("d", 64), CanonicalJSON: []byte(`{"generationId":"generation-a","sourcePointId":"point-a"}`), MaximumBytes: 4096, MaximumPUTs: 100, MaximumLISTs: 20, MaximumRetainedGenerations: 100, RuleLimit: 1000, RetentionSeconds: 86400, SessionTTLSeconds: 60, SourceRevision: 44, StateRevision: revision.StateRevision, RecoveryEpoch: revision.RecoveryEpoch}
	if err := repository.AppendRunSpec(ctx, runSpec); err != nil {
		t.Fatal(err)
	}
	storedRunSpec, err := repository.RunSpec(ctx, runSpec.GenerationID)
	if err != nil || storedRunSpec.SourcePointID != runSpec.SourcePointID || storedRunSpec.SourceRevision != 44 || storedRunSpec.StateRevision == storedRunSpec.SourceRevision || storedRunSpec.RepositoryKeyReferenceID != runSpec.RepositoryKeyReferenceID || string(storedRunSpec.CanonicalJSON) != string(runSpec.CanonicalJSON) {
		t.Fatalf("run spec round trip=%#v err=%v", storedRunSpec, err)
	}
	if _, err := backupRepository.store.conn.ExecContext(ctx, `UPDATE backup_offsite_run_specs SET source_point_id='wrong' WHERE generation_id=?`, runSpec.GenerationID); err == nil {
		t.Fatal("offsite run spec was mutable")
	}
	record := OffsiteGenerationRecord{GenerationID: "generation-a", SourcePointID: point.PointID, RepositoryID: strings.Repeat("7", 64), SnapshotID: strings.Repeat("8", 64),
		CanonicalJSON: []byte(`{"GenerationID":"generation-a"}`), Rules: []OffsiteRuleRecord{{"rule-1", "critical/generation-a/config"}, {"rule-2", "critical/generation-a/keys/"}, {"rule-3", "critical/generation-a/data/"}, {"rule-4", "critical/generation-a/index/"}, {"rule-5", "critical/generation-a/snapshots/"}},
		Objects: []OffsiteObjectRecord{{"config", "sha256:" + strings.Repeat("b", 64), 10}}, SessionExpiries: []time.Time{now.Add(time.Minute)}, SourceRevision: 44, StateRevision: revision.StateRevision,
		RecoveryEpoch: revision.RecoveryEpoch, IssuanceStoppedAt: now}
	if err := repository.AppendGeneration(ctx, record); err != nil {
		t.Fatal(err)
	}
	roundTrip, err := repository.Generation(ctx, record.GenerationID)
	if err != nil || roundTrip.StateRevision != record.StateRevision || len(roundTrip.Rules) != 5 || roundTrip.Rules[3] != record.Rules[3] || len(roundTrip.Objects) != 1 || roundTrip.Objects[0] != record.Objects[0] || len(roundTrip.SessionExpiries) != 1 || !roundTrip.SessionExpiries[0].Equal(record.SessionExpiries[0]) {
		t.Fatalf("generation round trip=%#v err=%v", roundTrip, err)
	}
	status, err := repository.Status(ctx, record.GenerationID)
	if err != nil || status.Status != "pending" || status.LastGoodProofID != "" {
		t.Fatalf("pending status=%#v err=%v", status, err)
	}
	proof := OffsiteProofRecord{ProofID: "proof-a", ProofDigest: "sha256:" + strings.Repeat("a", 64), GenerationID: record.GenerationID,
		Status: "offsite-verified", ProofClass: "qualified-provider", CanonicalJSON: []byte(`{"ProofID":"proof-a"}`), FullReadAt: now, ObservedAt: now, RecoveryEpoch: revision.RecoveryEpoch}
	if err := repository.AppendProof(ctx, proof); err != nil {
		t.Fatal(err)
	}
	if err := repository.AppendLastGood(ctx, proof.ProofID, proof.ProofDigest, record.GenerationID, record.SourceRevision, record.StateRevision+1, revision.RecoveryEpoch); err == nil {
		t.Fatal("stale state revision advanced offsite last-good")
	}
	if err := repository.AppendLastGood(ctx, proof.ProofID, proof.ProofDigest, record.GenerationID, record.SourceRevision, record.StateRevision, revision.RecoveryEpoch); err != nil {
		t.Fatal(err)
	}
	var storedSourceRevision, storedStateRevision int64
	if err := backupRepository.store.conn.QueryRowContext(ctx, `SELECT source_revision,state_revision FROM backup_offsite_last_good_history WHERE proof_id=?`, proof.ProofID).Scan(&storedSourceRevision, &storedStateRevision); err != nil || storedSourceRevision != record.SourceRevision || storedStateRevision != record.StateRevision {
		t.Fatalf("last-good revisions source=%d state=%d err=%v", storedSourceRevision, storedStateRevision, err)
	}
	status, err = repository.Status(ctx, record.GenerationID)
	if err != nil || status.Status != "offsite-verified" || status.ProofClass != "qualified-provider" || status.LastGoodProofID != proof.ProofID {
		t.Fatalf("verified status=%#v err=%v", status, err)
	}
	if _, err := backupRepository.store.conn.ExecContext(ctx, `UPDATE backup_offsite_proofs SET status='failed' WHERE proof_id='proof-a'`); err == nil {
		t.Fatal("offsite proof was mutable")
	}
	if _, err := backupRepository.store.conn.ExecContext(ctx, `UPDATE backup_offsite_objects SET object_bytes=11 WHERE generation_id='generation-a'`); err == nil {
		t.Fatal("offsite object inventory was mutable")
	}
	acquireFixtureLease(t, backupRepository, point.PolicyDigest, "writer-b", "job-b")
	if _, _, err := backupRepository.AppendPendingRecoveryPoint(ctx, pendingPointRequest("writer-b", "point-b", strings.Repeat("2", 64), point.PolicyDigest)); err != nil {
		t.Fatal(err)
	}
	second := record
	second.GenerationID, second.SourcePointID = "generation-b", "point-b"
	second.CanonicalJSON = []byte(`{"GenerationID":"generation-b"}`)
	second.Rules = append([]OffsiteRuleRecord(nil), record.Rules...)
	for index := range second.Rules {
		second.Rules[index].RuleID = strings.Replace(second.Rules[index].RuleID, "rule-", "other-", 1)
		second.Rules[index].Prefix = strings.Replace(second.Rules[index].Prefix, "generation-a", "generation-b", 1)
	}
	if err := repository.AppendGeneration(ctx, second); err != nil {
		t.Fatal(err)
	}
	secondStatus, err := repository.Status(ctx, second.GenerationID)
	if err != nil || secondStatus.LastGoodProofID != "" {
		t.Fatalf("unrelated generation inherited last-good: %#v %v", secondStatus, err)
	}
	local, err := backupRepository.ReadLocalBackupStatus(ctx)
	if err != nil || len(local.LastGood) != 0 || len(local.Offsite) != 2 {
		t.Fatalf("local/offsite projection=%#v err=%v", local, err)
	}
	for _, item := range local.Offsite {
		if item.GenerationID == second.GenerationID && item.LastGoodProofID != nil {
			t.Fatalf("epoch-global last-good leaked to %s", item.GenerationID)
		}
	}
}
