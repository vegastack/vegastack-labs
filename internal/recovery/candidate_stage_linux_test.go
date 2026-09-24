//go:build linux

package recovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type fileSnapshotReader struct {
	path, pointID, digest string
}

func (reader fileSnapshotReader) InspectAudit(context.Context) (AuditContinuity, error) {
	return AuditContinuity{}, nil
}

func (reader fileSnapshotReader) Restore(_ context.Context, target CandidateTarget, _ generated.RestoreBinding) (SnapshotReceipt, error) {
	destination, ok := CandidateTargetPath(target)
	if !ok {
		return SnapshotReceipt{}, os.ErrInvalid
	}
	source, err := os.Open(reader.path)
	if err != nil {
		return SnapshotReceipt{}, err
	}
	defer source.Close()
	candidate, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return SnapshotReceipt{}, err
	}
	written, copyErr := io.Copy(candidate, source)
	syncErr := candidate.Sync()
	closeErr := candidate.Close()
	if copyErr != nil {
		return SnapshotReceipt{}, copyErr
	}
	if syncErr != nil {
		return SnapshotReceipt{}, syncErr
	}
	if closeErr != nil {
		return SnapshotReceipt{}, closeErr
	}
	return SnapshotReceipt{PointID: reader.pointID, SnapshotID: "snapshot-a", ContentDigest: reader.digest, Bytes: written}, nil
}

type candidateRecorderStub struct{ receipt CandidateReceipt }

func (recorder *candidateRecorderStub) BindRecoveryCandidate(_ context.Context, _ generated.RestoreBinding, receipt CandidateReceipt) error {
	recorder.receipt = receipt
	return nil
}

func TestCandidateStageAndStartupPromotionBindMutatedSQLiteSemantically(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(directory, "control.db")
	config := func(path string, mode store.OpenMode) store.Config {
		return store.Config{DatabasePath: path, Mode: mode, BusyTimeout: 250 * time.Millisecond, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "candidate-test", BuildVersion: "candidate-test"}
	}
	authority, err := store.Open(ctx, config(databasePath, store.InitializeNew))
	if err != nil {
		t.Fatal(err)
	}
	prior, err := authority.CurrentAuthority(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.Close(); err != nil {
		t.Fatal(err)
	}
	snapshotPath := filepath.Join(directory, "source.db")
	if err := copyCandidateTestFile(databasePath, snapshotPath); err != nil {
		t.Fatal(err)
	}
	databaseDigest, err := candidateTestFileDigest(snapshotPath)
	if err != nil {
		t.Fatal(err)
	}
	binding := candidateTestBinding()
	binding.Source.RecoveryEpoch = prior.RecoveryEpoch
	binding.PriorRecoveryEpoch = prior.RecoveryEpoch
	binding.NextRecoveryEpoch = prior.RecoveryEpoch + 1
	binding.PriorInstanceID = prior.InstanceID
	recorder := &candidateRecorderStub{}
	opener := func(ctx context.Context, path string) (*store.Store, error) {
		return store.Open(ctx, config(path, store.OpenExisting))
	}
	manager := CandidateManager{DatabasePath: databasePath, Storage: LocalCandidateStorage{ExpectedUID: uint32(os.Geteuid())}, Records: recorder, Authority: StoreCandidateAuthority{Open: opener}}
	source := VerifiedSource{Binding: binding.Source, Snapshot: fileSnapshotReader{path: snapshotPath, pointID: binding.PointID, digest: databaseDigest}, DatabaseDigest: databaseDigest, Audit: AuditContinuity{IndependentCheckpointDigest: testCandidateDigest("9"), DecisionDigest: binding.AuditDecisionDigest}}
	receipt, err := manager.Stage(ctx, binding, source, FenceResult{FenceSetDigest: binding.FenceSetDigest})
	if err != nil {
		t.Fatal(err)
	}
	if receipt != recorder.receipt || receipt.CandidateDigest != binding.CandidateDigest || receipt.DatabaseDigest != databaseDigest {
		t.Fatalf("receipt=%#v recorded=%#v", receipt, recorder.receipt)
	}
	result, err := manager.PromoteAtStartup(ctx, StartupExpectation{Binding: binding, DatabaseDigest: databaseDigest, JournalDigest: receipt.JournalDigest})
	if err != nil {
		t.Fatal(err)
	}
	if result.InstanceID != binding.NewInstanceID || result.RecoveryEpoch != binding.NextRecoveryEpoch {
		t.Fatalf("promotion=%#v", result)
	}
	// A crash can happen after the no-replace rename but before the caller sees
	// success. Restart verifies the promoted authority and returns the same
	// result; it never restores the former writer automatically.
	result, err = manager.PromoteAtStartup(ctx, StartupExpectation{Binding: binding, DatabaseDigest: databaseDigest, JournalDigest: receipt.JournalDigest})
	if err != nil || result.InstanceID != binding.NewInstanceID || result.RecoveryEpoch != binding.NextRecoveryEpoch {
		t.Fatalf("promotion restart=%#v err=%v", result, err)
	}
	promoted, err := store.Open(ctx, config(databasePath, store.OpenExisting))
	if err != nil {
		t.Fatal(err)
	}
	defer promoted.Close()
	if err := promoted.VerifyRecoveredAuthority(ctx, binding); err != nil {
		t.Fatal(err)
	}
	health, err := promoted.Health(ctx)
	if err != nil || !health.RecoveryPending || health.MutationEnabled {
		t.Fatalf("health=%#v err=%v", health, err)
	}
}

func copyCandidateTestFile(sourcePath, destinationPath string) error {
	source, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer source.Close()
	destination, err := os.OpenFile(destinationPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(destination, source)
	syncErr := destination.Sync()
	closeErr := destination.Close()
	if copyErr != nil {
		return copyErr
	}
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func candidateTestFileDigest(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}
