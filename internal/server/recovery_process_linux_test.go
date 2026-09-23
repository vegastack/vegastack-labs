//go:build linux

package server

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/recovery"
)

const recoveryLockHelperEnvironment = "VSK_RECOVERY_LOCK_HELPER"

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
