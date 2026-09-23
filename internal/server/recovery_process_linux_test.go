//go:build linux

package server

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/recovery"
	"github.com/vegastack/vegastack-labs/internal/store"
)

const recoveryLockHelperEnvironment = "VSK_RECOVERY_LOCK_HELPER"
const recoveryAuthorityHelperEnvironment = "VSK_RECOVERY_AUTHORITY_HELPER"

// TestRecoveryPromotionLockIsExclusiveAcrossProcesses exercises the real
// no-follow flock used at startup. A second replacement process cannot enter
// promotion while the first owns the authority lock, and the lock becomes
// available only after the owner closes it.
func TestRecoveryPromotionLockIsExclusiveAcrossProcesses(t *testing.T) {
	if os.Getenv(recoveryLockHelperEnvironment) == "1" {
		runRecoveryLockHelper(t)
		return
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(directory, "control.db")
	paths, err := recovery.DeriveCandidatePaths(databasePath, "plan-process-a")
	if err != nil {
		t.Fatal(err)
	}
	storage := recovery.LocalCandidateStorage{ExpectedUID: uint32(os.Geteuid())}
	lock, err := storage.AcquireAuthorityLock(context.Background(), paths)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestRecoveryPromotionLockIsExclusiveAcrossProcesses$")
	command.Env = append(os.Environ(), recoveryLockHelperEnvironment+"=1", "VSK_RECOVERY_DATABASE="+databasePath, "VSK_RECOVERY_EXPECT_BLOCKED=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("blocked helper: %v: %s", err, output)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	command = exec.Command(os.Args[0], "-test.run=^TestRecoveryPromotionLockIsExclusiveAcrossProcesses$")
	command.Env = append(os.Environ(), recoveryLockHelperEnvironment+"=1", "VSK_RECOVERY_DATABASE="+databasePath)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("released helper: %v: %s", err, output)
	}
}

// TestReturningFormerControllerCannotMutatePromotedAuthority runs a
// replacement controller process against the promoted database while a
// separate returning-former process attempts an old-epoch write. The former
// process must observe the epoch denial and cannot become a second writer.
func TestReturningFormerControllerCannotMutatePromotedAuthority(t *testing.T) {
	if mode := os.Getenv(recoveryAuthorityHelperEnvironment); mode != "" {
		runRecoveryAuthorityHelper(t, mode)
		return
	}
	ctx := context.Background()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(directory, "control.db")
	config := func(path string, mode store.OpenMode) store.Config {
		return store.Config{DatabasePath: path, Mode: mode, BusyTimeout: 250 * time.Millisecond, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "recovery-process-test", BuildVersion: "recovery-process-test"}
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
	binding := processRecoveryBinding(prior.InstanceID, prior.RecoveryEpoch)
	opener := func(ctx context.Context, path string) (*store.Store, error) {
		return store.Open(ctx, config(path, store.OpenExisting))
	}
	if err := (recovery.StoreCandidateAuthority{Open: opener}).PrepareRecoveredAuthority(ctx, databasePath, binding, recovery.AuditContinuity{IndependentCheckpointDigest: processRecoveryDigest("9"), DecisionDigest: binding.AuditDecisionDigest}); err != nil {
		t.Fatal(err)
	}
	holder := exec.Command(os.Args[0], "-test.run=^TestReturningFormerControllerCannotMutatePromotedAuthority$")
	holder.Env = append(os.Environ(), recoveryAuthorityHelperEnvironment+"=replacement", "VSK_RECOVERY_DATABASE="+databasePath)
	holderIn, err := holder.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	holderOut, err := holder.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	if line, err := bufio.NewReader(holderOut).ReadString('\n'); err != nil || strings.TrimSpace(line) != "replacement-ready" {
		t.Fatalf("replacement start = %q, %v", line, err)
	}
	former := exec.Command(os.Args[0], "-test.run=^TestReturningFormerControllerCannotMutatePromotedAuthority$")
	former.Env = append(os.Environ(), recoveryAuthorityHelperEnvironment+"=former", "VSK_RECOVERY_DATABASE="+databasePath, "VSK_RECOVERY_PRIOR_EPOCH=0")
	if output, err := former.CombinedOutput(); err != nil {
		t.Fatalf("returning former mutated or failed ambiguously: %v: %s", err, output)
	}
	_ = holderIn.Close()
	if err := holder.Wait(); err != nil {
		t.Fatal(err)
	}
}

func runRecoveryAuthorityHelper(t *testing.T, mode string) {
	path := os.Getenv("VSK_RECOVERY_DATABASE")
	authority, err := store.Open(context.Background(), store.Config{DatabasePath: path, Mode: store.OpenExisting, BusyTimeout: 250 * time.Millisecond, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "recovery-process-test", BuildVersion: "recovery-process-test"})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	switch mode {
	case "replacement":
		if health, err := authority.Health(context.Background()); err != nil || !health.RecoveryPending || health.MutationEnabled || health.Revision.RecoveryEpoch != 1 {
			t.Fatalf("replacement health = %#v, %v", health, err)
		}
		_, _ = os.Stdout.WriteString("replacement-ready\n")
		_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	case "former":
		health, err := authority.Health(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		prior := store.RevisionToken{StateRevision: health.Revision.StateRevision, RecoveryEpoch: 0}
		if _, err := authority.WriteIntent(context.Background(), &prior, func(store.IntentTx) error { return nil }); store.Code(err) != generated.ErrorCodeRecoveryEpochMismatch {
			t.Fatalf("former write code = %s", store.Code(err))
		}
	default:
		t.Fatal("unknown helper mode")
	}
}

func processRecoveryBinding(priorInstance string, priorEpoch int64) generated.RestoreBinding {
	source := generated.RestoreSourceBinding{Schema: generated.SchemaIDRestoreSourceBinding, SchemaVersion: "1.1.0", PointID: "point-process", PointDigest: processRecoveryDigest("1"), ManifestDigest: processRecoveryDigest("2"), VerificationDigest: processRecoveryDigest("3"), SourceClass: "local", RepositoryGenerationID: "generation-process", KeyReferenceID: "key-process", DeclaredRPOSeconds: 3600, CreatedAt: "2026-09-24T05:00:00Z", VerifiedAt: "2026-09-24T05:30:00Z", RecoveryEpoch: priorEpoch, DependencyDigests: []string{processRecoveryDigest("4")}, RequiredDependencies: []generated.RestoreDependencyBinding{{DependencyID: "restic-binary", Kind: "binary", Digest: processRecoveryDigest("4")}}, TargetReleaseBuildID: "build-process", TargetToolVersion: "1.0.0", TargetSchemaVersion: "24"}
	return generated.RestoreBinding{Schema: generated.SchemaIDRestoreBinding, SchemaVersion: "1.1.0", Source: source, PointID: source.PointID, DependencyIDs: []string{"dependency-process"}, TargetIDs: []string{"control-process"}, TargetDigest: processRecoveryDigest("5"), PlanID: "plan-process", PlanDigest: processRecoveryDigest("a"), HumanAcknowledgementID: "ack-process", FenceSetDigest: processRecoveryDigest("b"), AuditDecisionDigest: processRecoveryDigest("c"), CandidateDigest: processRecoveryDigest("d"), FormerHostID: "former-host", ReplacementHostID: "replacement-host", RecoveryDraftID: "draft-process", CiphertextFingerprint: processRecoveryDigest("e"), SourceAdmissionDigest: processRecoveryDigest("f"), FenceQualificationDigest: processRecoveryDigest("1"), RecoveryRunID: "run-process", RecoveryStepID: "step-process", RecoveryLeaseID: "lease-process", RecoveryChallengeID: "challenge-process", RecoveryReceiptID: "receipt-process", CanaryRunID: "canary-run-process", CanaryStepID: "canary-step-process", CanaryLeaseID: "canary-lease-process", CanaryChallengeID: "canary-challenge-process", CanaryReceiptID: "canary-receipt-process", CanaryBindingDigest: processRecoveryDigest("2"), PriorInstanceID: priorInstance, NewInstanceID: "instance-replacement-process", PriorRecoveryEpoch: priorEpoch, NextRecoveryEpoch: priorEpoch + 1, Status: "planned"}
}

func processRecoveryDigest(letter string) string { return "sha256:" + strings.Repeat(letter, 64) }

func runRecoveryLockHelper(t *testing.T) {
	paths, err := recovery.DeriveCandidatePaths(os.Getenv("VSK_RECOVERY_DATABASE"), "plan-process-a")
	if err != nil {
		t.Fatal(err)
	}
	lock, err := (recovery.LocalCandidateStorage{ExpectedUID: uint32(os.Geteuid())}).AcquireAuthorityLock(context.Background(), paths)
	if os.Getenv("VSK_RECOVERY_EXPECT_BLOCKED") == "1" {
		if err == nil {
			_ = lock.Close()
			t.Fatal("second recovery process acquired the authority lock")
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
}
