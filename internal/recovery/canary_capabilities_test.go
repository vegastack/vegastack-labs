package recovery

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type checkpointCapabilityFixture struct {
	checkpoint generated.AuditCheckpoint
	eventID    int64
	eventAt    time.Time
}

func (fixture checkpointCapabilityFixture) AppendRecoveryCheckpoint(context.Context, CanaryRequest, string) (string, error) {
	return fixture.checkpoint.CheckpointID, nil
}
func (fixture checkpointCapabilityFixture) GetAuditCheckpoint(context.Context, string) (generated.AuditCheckpoint, error) {
	return fixture.checkpoint, nil
}
func (fixture checkpointCapabilityFixture) RecoveryCanaryNoopEvent(context.Context, string, string) (int64, time.Time, error) {
	return fixture.eventID, fixture.eventAt, nil
}

type backupCapabilityFixture struct{ source store.LocalRecoverySource }

func (fixture backupCapabilityFixture) CreateRecoveryBackup(context.Context, CanaryRequest) (string, string, error) {
	return fixture.source.Point.PointID, fixture.source.Point.RepositoryClass, nil
}
func (fixture backupCapabilityFixture) CurrentLocalRecoverySource(context.Context, string) (store.LocalRecoverySource, error) {
	return fixture.source, nil
}

func TestQualifiedCanaryCapabilitiesRequireIndependentCurrentEpochReadback(t *testing.T) {
	started := time.Date(2026, 9, 24, 4, 59, 0, 0, time.UTC)
	request := CanaryRequest{PlanID: "plan-a", NewInstanceID: "instance-new", RecoveryEpoch: 3, ExpectedStateRevision: 19, CanaryRunID: "canary-run-a", CanaryStepID: "canary-step-a", StartedAt: started}
	digest, stamp := testDigest("a"), "2026-09-24T05:00:00Z"
	checkpoint := generated.AuditCheckpoint{CheckpointID: "checkpoint-a", FirstEventID: 7, LastEventID: 11, InstanceID: request.NewInstanceID, RecoveryEpoch: request.RecoveryEpoch, Status: "anchored", VerificationStatus: "verified", SourceKind: "independent", ProofClass: "live", SignatureDigest: &digest, ExportReceiptDigest: &digest, IndependentReadDigest: &digest, IndependentCopyDigest: &digest, VerifiedAt: &stamp}
	auditCapability := checkpointCapabilityFixture{checkpoint: checkpoint, eventID: 9, eventAt: started.Add(30 * time.Second)}
	if id, err := (IndependentCheckpointCanary{Appender: auditCapability, Reader: auditCapability}).AppendAndVerifyRecoveryCheckpoint(context.Background(), request, "canary-run-a"); err != nil || id != checkpoint.CheckpointID {
		t.Fatalf("checkpoint = %q, %v", id, err)
	}
	checkpoint.RecoveryEpoch--
	auditCapability.checkpoint = checkpoint
	if _, err := (IndependentCheckpointCanary{Appender: auditCapability, Reader: auditCapability}).AppendAndVerifyRecoveryCheckpoint(context.Background(), request, "canary-run-a"); err == nil {
		t.Fatal("old-epoch checkpoint accepted")
	}
	checkpoint.RecoveryEpoch = request.RecoveryEpoch
	checkpoint.FirstEventID = 10
	auditCapability.checkpoint = checkpoint
	if _, err := (IndependentCheckpointCanary{Appender: auditCapability, Reader: auditCapability}).AppendAndVerifyRecoveryCheckpoint(context.Background(), request, "canary-run-a"); err == nil {
		t.Fatal("checkpoint without the exact noop event accepted")
	}

	now := time.Date(2026, 9, 24, 5, 0, 0, 0, time.UTC)
	manifest, _ := json.Marshal(struct {
		RunID  string `json:"runId"`
		StepID string `json:"stepId"`
	}{request.CanaryRunID, request.CanaryStepID})
	source := store.LocalRecoverySource{Point: store.PendingRecoveryPoint{PointID: "point-a", RepositoryClass: "standard", RecoveryEpoch: request.RecoveryEpoch, ManifestJSON: manifest}, Verification: store.LocalVerificationReceipt{PointID: "point-a", RecoveryEpoch: request.RecoveryEpoch, StateRevision: request.ExpectedStateRevision, Status: "local-verified", ProofClass: "live"}, CreatedAt: now, VerifiedAt: now, FullReadAt: now, FunctionalRestoredAt: now}
	backupCapability := backupCapabilityFixture{source: source}
	if id, err := (CurrentEpochBackupCanary{Creator: backupCapability, Reader: backupCapability}).CreateAndVerifyRecoveryBackup(context.Background(), request); err != nil || id != source.Point.PointID {
		t.Fatalf("backup = %q, %v", id, err)
	}
	source.Verification.ProofClass = "fixture"
	backupCapability.source = source
	if _, err := (CurrentEpochBackupCanary{Creator: backupCapability, Reader: backupCapability}).CreateAndVerifyRecoveryBackup(context.Background(), request); err == nil {
		t.Fatal("fixture backup accepted")
	}
	source.Verification.ProofClass = "live"
	source.CreatedAt = started.Add(-time.Second)
	backupCapability.source = source
	if _, err := (CurrentEpochBackupCanary{Creator: backupCapability, Reader: backupCapability}).CreateAndVerifyRecoveryBackup(context.Background(), request); err == nil {
		t.Fatal("pre-canary backup accepted")
	}
}

func testDigest(letter string) string { return "sha256:" + strings.Repeat(letter, 64) }
