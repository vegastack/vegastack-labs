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
	digest := "sha256:" + strings.Repeat("a", 64)
	draftRequest := validDeclarationStoreRequest()
	draftRequest.Document.DeclarationID = "declaration-offsite-a"
	draftRequest.Document.DeclarationType = "backup.offsite"
	draftRequest.Document.StateRevision = revision.StateRevision + 1
	draftRequest.Document.RecoveryEpoch = revision.RecoveryEpoch
	draftRequest.Document.Operations = []generated.DeclarationOperation{{Sequence: 1, OperationID: "operation-offsite-a", OperationType: "backup.offsite.copy", AdapterID: "labs.r2-offsite", TargetID: "generation-plan-a", InputDigest: digest, ArtifactDigest: digest, Idempotent: false,
		OffsiteRunSpec: &generated.OffsiteRunSpec{GenerationID: "generation-plan-a", SourcePointID: point.PointID, SnapshotPath: "/var/lib/vsk-labs/offsite/source-a", RepositoryURL: "s3:https://account.r2.cloudflarestorage.com/bucket-a/critical/generation-plan-a", ParentReferenceID: "parent-a", RepositoryKeyReferenceID: "password-a", ObserverReferenceID: "observer-a", RuleDigest: digest, G008EvidenceDigest: digest, MaximumBytes: 4096, MaximumPUTs: 100, MaximumLISTs: 20, MaximumRetainedGenerations: 100, RuleLimit: 1000, RetentionSeconds: 86400, SessionTTLSeconds: 60}}}
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
	if err != nil || stored.SourcePointID != point.PointID || stored.RepositoryKeyReferenceID != "password-a" || stored.StateRevision != planRequest.Plan.Binding.StateRevision {
		t.Fatalf("production run spec = %#v, %v", stored, err)
	}
}

func TestOffsiteRepositoryPersistsAppendOnlyReceiptsAndCASLastGood(t *testing.T) {
	ctx := context.Background()
	backupRepository, point, revision := seededVerificationPoint(t)
	repository := NewOffsiteRepository(backupRepository.store)
	now := time.Now().UTC().Truncate(time.Second)
	runSpec := OffsiteRunSpecRecord{GenerationID: "generation-a", SourcePointID: point.PointID, SnapshotPath: "/var/lib/vsk-labs/offsite/source-a", RepositoryURL: "s3:https://account.r2.cloudflarestorage.com/bucket-a/critical/generation-a", ParentReferenceID: "parent-a", RepositoryKeyReferenceID: "password-a",
		RuleDigest: "sha256:" + strings.Repeat("c", 64), G008EvidenceDigest: "sha256:" + strings.Repeat("d", 64), CanonicalJSON: []byte(`{"generationId":"generation-a","sourcePointId":"point-a"}`), MaximumBytes: 4096, MaximumPUTs: 100, MaximumLISTs: 20, MaximumRetainedGenerations: 100, RuleLimit: 1000, RetentionSeconds: 86400, SessionTTLSeconds: 60, StateRevision: revision.StateRevision, RecoveryEpoch: revision.RecoveryEpoch}
	if err := repository.AppendRunSpec(ctx, runSpec); err != nil {
		t.Fatal(err)
	}
	storedRunSpec, err := repository.RunSpec(ctx, runSpec.GenerationID)
	if err != nil || storedRunSpec.SourcePointID != runSpec.SourcePointID || storedRunSpec.RepositoryKeyReferenceID != runSpec.RepositoryKeyReferenceID || string(storedRunSpec.CanonicalJSON) != string(runSpec.CanonicalJSON) {
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
