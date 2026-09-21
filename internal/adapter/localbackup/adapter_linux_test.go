//go:build linux

package localbackup

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/backup"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/stateexport"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type fixedPlanSource struct{ plan generated.Plan }

func (source fixedPlanSource) GetPlan(_ context.Context, id string) (store.PlanCommitResult, error) {
	if id != source.plan.PlanID {
		return store.PlanCommitResult{}, os.ErrNotExist
	}
	return store.PlanCommitResult{Plan: source.plan}, nil
}

// TestLocalBackupComposition uses the real store-owned SQLite Online Backup,
// policy draft/plan binding, writer lease, pinned restic child and guarded REST
// boundary. It catches horizontal tests that pass while production composition
// cannot publish a second exact pending point.
func TestLocalBackupComposition(t *testing.T) {
	binary := os.Getenv("VSK_RESTIC_0191_BINARY")
	if binary == "" {
		t.Skip("official pinned restic 0.19.1 binary not provided")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	root := t.TempDir()
	uid := uint32(os.Geteuid())
	authority, err := store.Open(ctx, store.Config{
		DatabasePath: filepath.Join(root, "control.db"), Mode: store.InitializeNew,
		ExpectedUID: uid, BusyTimeout: 5 * time.Second, ToolVersion: "test", BuildVersion: "test",
	})
	if err != nil {
		t.Fatalf("open authority: %v", err)
	}
	defer authority.Close()
	backups := store.NewBackupRepository(authority)
	snapshots, err := store.NewOnlineSnapshotSource(authority)
	if err != nil {
		t.Fatal(err)
	}
	keyID, recoveryID, repositoryID := "enc-a", "recovery-a", "repo-real"
	policy := generated.BackupPolicy{
		Schema: generated.SchemaIDBackupPolicy, SchemaVersion: "1.1.0",
		PolicyID: "policy-real", OwnerID: "owner-real", SourceID: "source-real",
		SourceSelectors: []string{"control-database"}, ConsistencyHookID: backup.SQLiteOnlineHookID,
		RepositoryID: &repositoryID, RepositoryClass: "standard", ScheduleIntent: "manual",
		ExpectedBytes: 4 << 20, ExpectedGrowthBytes: 4 << 20, MinimumFreeBytes: 4 << 20,
		EncryptionKeyReferenceID: &keyID, RecoveryKeyReferenceID: &recoveryID,
		RetentionDays: 7, RestoreTargetID: "isolated-test",
		Dependencies:           []generated.BackupDependency{{DependencyID: "binary-restic", Kind: "binary", Digest: "sha256:" + strings.Repeat("a", 64)}},
		FunctionalTestRequired: true, RecoveryEpoch: 0, Revision: 1,
	}
	_, policySum, err := stateexport.CanonicalJSON(policy)
	if err != nil {
		t.Fatal(err)
	}
	submission, err := backups.CreateBackupPolicyDraft(ctx, generated.BackupPolicyDraftRequest{
		Schema: generated.SchemaIDBackupPolicyDraftRequest, SchemaVersion: "1.1.0",
		ExpectedStateRevision: 0, RecoveryEpoch: 0, TargetDigest: "sha256:" + hex.EncodeToString(policySum[:]),
		IdempotencyKey: "draft-real", Policy: policy,
	}, audit.Attribution{AuthenticatedPrincipalID: "human-test", AuthenticatedPrincipalMethod: "local-os-peer"})
	if err != nil {
		t.Fatalf("draft: %v", err)
	}
	standard := filepath.Join(root, "standard")
	critical := filepath.Join(root, "critical")
	for _, path := range []string{standard, critical} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	planDigest := "sha256:" + strings.Repeat("b", 64)
	plan := generated.Plan{PlanID: "plan-real", PlanDigest: planDigest,
		Binding:    generated.PlanBinding{RecoveryEpoch: 0, StateRevision: submission.StateRevision},
		Extensions: []generated.ContractExtension{{Name: "x-backup-policy", ValueDigest: submission.PolicyDigest}}}
	implementation, err := New(Config{
		LocalBackup: &serverconfig.LocalBackup{StandardRoot: standard, CriticalRoot: critical, ResticBinaryPath: binary},
		ExpectedUID: uid, Backups: backups, Snapshots: snapshots, Plans: fixedPlanSource{plan},
		Hooks: backup.DefaultHookRegistry(), Runner: backup.NewResticRunner(), Clock: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	operation := adapter.Operation{OperationType: OperationType, AdapterID: AdapterID, TargetID: "control-test",
		SecretReferences: []adapter.SecretReference{{ID: keyID, Consumer: AdapterID}}}
	var firstPoint string
	for attempt := 1; attempt <= 2; attempt++ {
		password, err := credentialref.NewValue([]byte("isolated-composition-password"))
		if err != nil {
			t.Fatal(err)
		}
		binding := adapter.ExactExecutionBinding{PlanID: plan.PlanID, PlanDigest: planDigest,
			RunID: "run-" + string(rune('0'+attempt)), StepID: "step-" + string(rune('0'+attempt)),
			LeaseID: "executor-" + string(rune('0'+attempt)), StateRevision: submission.StateRevision,
			RecoveryEpoch: 0, MaximumExpiresAt: time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339)}
		effect, runErr := implementation.ExecuteBoundWithCredentials(ctx, operation, binding, []*credentialref.Value{password})
		password.Close()
		if runErr != nil || effect.PendingPointID == nil || effect.Status != "succeeded" {
			t.Fatalf("attempt %d effect=%#v err=%v", attempt, effect, runErr)
		}
		verification, err := implementation.Verify(ctx, operation, effect)
		if err != nil || !verification.Verified {
			t.Fatalf("attempt %d readback verify=%#v err=%v", attempt, verification, err)
		}
		point, err := backups.GetPendingRecoveryPoint(ctx, *effect.PendingPointID)
		if err != nil || point.ManifestDigest != effect.ResultDigest || len(point.ExpectedObjects) < 3 {
			t.Fatalf("attempt %d point=%#v err=%v", attempt, point, err)
		}
		if attempt == 1 {
			firstPoint = point.PointID
		} else if point.PointID == firstPoint {
			t.Fatal("second point reused the first point ID")
		}
	}
	if _, err := backups.GetPendingRecoveryPoint(ctx, firstPoint); err != nil {
		t.Fatalf("second point lost first pending point: %v", err)
	}
}
