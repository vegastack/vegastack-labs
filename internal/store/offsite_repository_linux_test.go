//go:build linux

package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestOffsiteRepositoryPersistsAppendOnlyReceiptsAndCASLastGood(t *testing.T) {
	ctx := context.Background()
	backupRepository, point, revision := seededVerificationPoint(t)
	repository := NewOffsiteRepository(backupRepository.store)
	now := time.Now().UTC().Truncate(time.Second)
	record := OffsiteGenerationRecord{GenerationID: "generation-a", SourcePointID: point.PointID, RepositoryID: strings.Repeat("7", 64), SnapshotID: strings.Repeat("8", 64),
		CanonicalJSON: []byte(`{"GenerationID":"generation-a"}`), SessionExpiries: []time.Time{now.Add(time.Minute)}, SourceRevision: revision.StateRevision,
		RecoveryEpoch: revision.RecoveryEpoch, IssuanceStoppedAt: now}
	if err := repository.AppendGeneration(ctx, record); err != nil {
		t.Fatal(err)
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
	if err := repository.AppendLastGood(ctx, proof.ProofID, proof.ProofDigest, record.GenerationID, revision.StateRevision, revision.StateRevision+1, revision.RecoveryEpoch); err == nil {
		t.Fatal("stale state revision advanced offsite last-good")
	}
	if err := repository.AppendLastGood(ctx, proof.ProofID, proof.ProofDigest, record.GenerationID, revision.StateRevision, revision.StateRevision, revision.RecoveryEpoch); err != nil {
		t.Fatal(err)
	}
	status, err = repository.Status(ctx, record.GenerationID)
	if err != nil || status.Status != "offsite-verified" || status.ProofClass != "qualified-provider" || status.LastGoodProofID != proof.ProofID {
		t.Fatalf("verified status=%#v err=%v", status, err)
	}
	if _, err := backupRepository.store.conn.ExecContext(ctx, `UPDATE backup_offsite_proofs SET status='failed' WHERE proof_id='proof-a'`); err == nil {
		t.Fatal("offsite proof was mutable")
	}
	local, err := backupRepository.ReadLocalBackupStatus(ctx)
	if err != nil || len(local.LastGood) != 0 || len(local.Offsite) != 1 || local.Offsite[0].LastGoodProofID == nil || *local.Offsite[0].LastGoodProofID != proof.ProofID {
		t.Fatalf("local/offsite projection=%#v err=%v", local, err)
	}
}
