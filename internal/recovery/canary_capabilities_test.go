package recovery

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type checkpointCapabilityFixture struct{ checkpoint generated.AuditCheckpoint }

func (fixture checkpointCapabilityFixture) AppendRecoveryCheckpoint(context.Context, CanaryRequest, string) (string, error) {
	return fixture.checkpoint.CheckpointID, nil
}
func (fixture checkpointCapabilityFixture) GetAuditCheckpoint(context.Context, string) (generated.AuditCheckpoint, error) {
	return fixture.checkpoint, nil
}

type backupCapabilityFixture struct{ source store.LocalRecoverySource }

func (fixture backupCapabilityFixture) CreateRecoveryBackup(context.Context, CanaryRequest) (string, string, error) {
	return fixture.source.Point.PointID, fixture.source.Point.RepositoryClass, nil
}
func (fixture backupCapabilityFixture) CurrentLocalRecoverySource(context.Context, string) (store.LocalRecoverySource, error) {
	return fixture.source, nil
}

func TestQualifiedCanaryCapabilitiesRequireIndependentCurrentEpochReadback(t *testing.T) {
	request := CanaryRequest{NewInstanceID: "instance-new", RecoveryEpoch: 3, ExpectedStateRevision: 19}
	digest, stamp := testDigest("a"), "2026-09-24T05:00:00Z"
	checkpoint := generated.AuditCheckpoint{CheckpointID: "checkpoint-a", InstanceID: request.NewInstanceID, RecoveryEpoch: request.RecoveryEpoch, Status: "anchored", VerificationStatus: "verified", SourceKind: "independent", ProofClass: "live", SignatureDigest: &digest, ExportReceiptDigest: &digest, IndependentReadDigest: &digest, IndependentCopyDigest: &digest, VerifiedAt: &stamp}
	auditCapability := checkpointCapabilityFixture{checkpoint: checkpoint}
	if id, err := (IndependentCheckpointCanary{Appender: auditCapability, Reader: auditCapability}).AppendAndVerifyRecoveryCheckpoint(context.Background(), request, "canary-run-a"); err != nil || id != checkpoint.CheckpointID {
		t.Fatalf("checkpoint = %q, %v", id, err)
	}
	checkpoint.RecoveryEpoch--
	auditCapability.checkpoint = checkpoint
	if _, err := (IndependentCheckpointCanary{Appender: auditCapability, Reader: auditCapability}).AppendAndVerifyRecoveryCheckpoint(context.Background(), request, "canary-run-a"); err == nil {
		t.Fatal("old-epoch checkpoint accepted")
	}

	now := time.Date(2026, 9, 24, 5, 0, 0, 0, time.UTC)
	source := store.LocalRecoverySource{Point: store.PendingRecoveryPoint{PointID: "point-a", RepositoryClass: "standard", RecoveryEpoch: request.RecoveryEpoch}, Verification: store.LocalVerificationReceipt{PointID: "point-a", RecoveryEpoch: request.RecoveryEpoch, StateRevision: request.ExpectedStateRevision, Status: "local-verified", ProofClass: "live"}, FullReadAt: now, FunctionalRestoredAt: now}
	backupCapability := backupCapabilityFixture{source: source}
	if id, err := (CurrentEpochBackupCanary{Creator: backupCapability, Reader: backupCapability}).CreateAndVerifyRecoveryBackup(context.Background(), request); err != nil || id != source.Point.PointID {
		t.Fatalf("backup = %q, %v", id, err)
	}
	source.Verification.ProofClass = "fixture"
	backupCapability.source = source
	if _, err := (CurrentEpochBackupCanary{Creator: backupCapability, Reader: backupCapability}).CreateAndVerifyRecoveryBackup(context.Background(), request); err == nil {
		t.Fatal("fixture backup accepted")
	}
}

func testDigest(letter string) string { return "sha256:" + strings.Repeat(letter, 64) }
