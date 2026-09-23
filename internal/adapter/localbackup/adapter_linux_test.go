//go:build linux

package localbackup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/backup"
	"github.com/vegastack/vegastack-labs/internal/backupidentity"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/stateexport"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func init() {
	if len(os.Args) == 2 && os.Args[1] == backup.CustodyPolicyCheckMode {
		os.Exit(backup.RunCustodyPolicyCheck(context.Background(), os.Stdin))
	}
	if os.Getenv("VSK_BACKUP_CUSTODY_SUPERVISOR") == "1" {
		if len(os.Args) != 3 || os.Args[1] != backup.CustodySystemdMode {
			os.Exit(1)
		}
		if err := backup.RunCustodySupervisor(os.Args[2]); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if os.Getenv("VSK_BACKUP_CUSTODY") == "1" {
		if err := backup.RunCustodyChild(os.Getenv("VSK_BACKUP_CUSTODY_POLICY")); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
}

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
	systemdFixture := os.Getenv("VSK_CUSTODY_SYSTEMD_FIXTURE") == "1"
	if !systemdFixture && os.Geteuid() != 0 {
		t.Skip("distinct-UID custody acceptance requires disposable root")
	}
	if systemdFixture && os.Geteuid() != 21164 {
		t.Fatalf("systemd fixture controller uid=%d want=21164", os.Geteuid())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	currentTime := time.Now().UTC().Truncate(time.Second)
	operationTime := currentTime.Add(-8 * 24 * time.Hour)
	clock := func() time.Time {
		if operationTime.IsZero() {
			return time.Now()
		}
		return operationTime
	}
	root := "/var/lib/vsk163-systemd"
	var err error
	if !systemdFixture {
		root, err = os.MkdirTemp("/var/lib", "vsk-localbackup-custody-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(root) })
		if err := os.Chmod(root, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	uid := uint32(os.Geteuid())
	controlRoot := filepath.Join(root, "control")
	if err := os.Mkdir(controlRoot, 0o700); err != nil && !systemdFixture {
		t.Fatal(err)
	}
	authority, err := store.Open(ctx, store.Config{
		DatabasePath: filepath.Join(controlRoot, "control.db"), Mode: store.InitializeNew,
		ExpectedUID: uid, BusyTimeout: 5 * time.Second, ToolVersion: "test", BuildVersion: "test",
		Clock: clock,
	})
	if err != nil {
		t.Fatalf("open authority: %v; cause=%v", err, errors.Unwrap(err))
	}
	defer authority.Close()
	backups := store.NewBackupRepository(authority)
	snapshots, err := store.NewOnlineSnapshotSource(authority)
	if err != nil {
		t.Fatal(err)
	}
	inspector, err := store.NewRestoredSQLiteInspector(authority)
	if err != nil {
		t.Fatal(err)
	}
	var filesystem unix.Statfs_t
	err = unix.Statfs(root, &filesystem)
	freeBefore := uint64(filesystem.Bavail) * uint64(filesystem.Bsize)
	if err != nil || freeBefore < 256<<20 || freeBefore > math.MaxInt64 {
		t.Skip("disposable filesystem lacks bounded capacity-fixture headroom")
	}
	keyID, recoveryID, repositoryID := "enc-a", "recovery-a", backupidentity.StandardRepository
	policy := generated.BackupPolicy{
		Schema: generated.SchemaIDBackupPolicy, SchemaVersion: "1.2.0",
		PolicyID: "policy-real", OwnerID: "owner-real", SourceID: backupidentity.ControlDatabaseSource,
		SourceSelectors: []string{backupidentity.ControlDatabaseSelector}, ConsistencyHookID: backup.SQLiteOnlineHookID,
		RepositoryID: &repositoryID, RepositoryClass: "standard", ScheduleIntent: "manual",
		ExpectedBytes: 4 << 20, ExpectedGrowthBytes: 4 << 20, MinimumFreeBytes: int64(freeBefore) - (72 << 20),
		EncryptionKeyReferenceID: &keyID, RecoveryKeyReferenceID: &recoveryID,
		RetentionDays: 7, RestoreTargetID: "isolated-test",
		Dependencies:           []generated.BackupDependency{{DependencyID: "binary-restic", Kind: "binary", Digest: pinnedResticDigest()}},
		FunctionalTestRequired: true, FullPayloadIntervalHours: 24, FunctionalTestIntervalHours: 168, RecoveryEpoch: 0, Revision: 1,
	}
	for name, mutate := range map[string]func(*generated.BackupPolicy){
		"foreign source":     func(p *generated.BackupPolicy) { p.SourceID = "source-foreign" },
		"foreign selector":   func(p *generated.BackupPolicy) { p.SourceSelectors = []string{"selector-foreign"} },
		"foreign repository": func(p *generated.BackupPolicy) { id := "repo-foreign"; p.RepositoryID = &id },
	} {
		t.Run(name, func(t *testing.T) {
			foreign := policy
			mutate(&foreign)
			_, sum, err := stateexport.CanonicalJSON(foreign)
			if err != nil {
				t.Fatal(err)
			}
			_, err = backups.CreateBackupPolicyDraft(ctx, generated.BackupPolicyDraftRequest{Schema: generated.SchemaIDBackupPolicyDraftRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: 0, RecoveryEpoch: 0, TargetDigest: "sha256:" + hex.EncodeToString(sum[:]), IdempotencyKey: "foreign-" + name, Policy: foreign}, audit.Attribution{AuthenticatedPrincipalID: "human-test", AuthenticatedPrincipalMethod: "local-os-peer"})
			if store.Code(err) != generated.ErrorCodeInputInvalid {
				t.Fatalf("unregistered identity admitted: %v", err)
			}
		})
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
	standardQ, criticalQ := filepath.Join(root, "standard-q"), filepath.Join(root, "critical-q")
	const custodyUID, controllerUID, resticUID = uint32(21163), uint32(21164), uint32(21165)
	if !systemdFixture {
		for _, path := range []string{standard, critical, standardQ, criticalQ} {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(path, int(custodyUID), int(custodyUID)); err != nil {
				t.Fatal(err)
			}
		}
	}
	custodyPath := backup.CustodyPolicyPath
	if !systemdFixture {
		executable, err := os.ReadFile("/proc/self/exe")
		if err != nil {
			t.Fatal(err)
		}
		executableSum := sha256.Sum256(executable)
		custody := backup.CustodyPolicy{SchemaVersion: "1.0.0", StandardRoot: standard, CriticalRoot: critical, StandardQuarantine: standardQ, CriticalQuarantine: criticalQ,
			OwnerUID: custodyUID, OwnerGID: custodyUID, ControllerUID: controllerUID, ResticUID: resticUID,
			RequestRoot: filepath.Join(root, "requests"), ExchangeRoot: filepath.Join(root, "exchange"), UnitTemplate: "vsk-labs-backup-custody@.service",
			ExecutablePath: "/proc/self/exe", ResticBinaryPath: binary, ExecutableDigest: "sha256:" + hex.EncodeToString(executableSum[:]), MaximumLifetime: 10 * time.Minute}
		custodyBody, _ := json.Marshal(custody)
		custodyPath = filepath.Join(root, "custody.json")
		if err := os.WriteFile(custodyPath, custodyBody, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	planDigest := "sha256:" + strings.Repeat("b", 64)
	plan := generated.Plan{PlanID: "plan-real", PlanDigest: planDigest,
		Binding:    generated.PlanBinding{RecoveryEpoch: 0, StateRevision: submission.StateRevision},
		Extensions: []generated.ContractExtension{{Name: "x-backup-policy", ValueDigest: submission.PolicyDigest}}}
	implementation, err := New(Config{
		LocalBackup: &serverconfig.LocalBackup{StandardRoot: standard, CriticalRoot: critical, ResticBinaryPath: binary, CustodyPolicyPath: custodyPath,
			SourceID: backupidentity.ControlDatabaseSource, StandardRepositoryID: backupidentity.StandardRepository,
			CriticalRepositoryID: backupidentity.CriticalRepository},
		ExpectedUID: controllerUID, Backups: backups, Snapshots: snapshots, Inspector: inspector, Plans: fixedPlanSource{plan},
		Hooks: backup.DefaultHookRegistry(), Runner: backup.NewResticRunner(), Clock: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	operation := adapter.Operation{OperationType: OperationType, AdapterID: AdapterID, TargetID: "control-test",
		SecretReferences: []adapter.SecretReference{{ID: keyID, Consumer: AdapterID}}}
	invalidProfile := *implementation.config.LocalBackup
	invalidProfile.SourceID = "source-foreign"
	invalidConfig := implementation.config
	invalidConfig.LocalBackup = &invalidProfile
	invalidAdapter, err := New(invalidConfig)
	if err != nil {
		t.Fatal(err)
	}
	invalidPassword, err := credentialref.NewValue([]byte("isolated-composition-password"))
	if err != nil {
		t.Fatal(err)
	}
	invalidBinding := adapter.ExactExecutionBinding{PlanID: plan.PlanID, PlanDigest: planDigest, RunID: "run-invalid-profile", StepID: "step-invalid-profile", StateRevision: submission.StateRevision, RecoveryEpoch: 0}
	_, err = invalidAdapter.ExecuteBoundWithCredentials(ctx, operation, invalidBinding, []*credentialref.Value{invalidPassword})
	invalidPassword.Close()
	if err == nil {
		t.Fatal("unregistered protected profile reached a backup lease")
	}
	var firstPoint, secondPoint string
	for attempt := 1; attempt <= 2; attempt++ {
		if attempt == 2 {
			operationTime = time.Time{}
		}
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
			t.Fatalf("attempt %d effect=%#v err=%v cause=%v", attempt, effect, runErr, errors.Unwrap(runErr))
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
		} else {
			secondPoint = point.PointID
		}
	}
	if _, err := backups.GetPendingRecoveryPoint(ctx, firstPoint); err != nil {
		t.Fatalf("second point lost first pending point: %v", err)
	}
	first, err := backups.GetPendingRecoveryPoint(ctx, firstPoint)
	if err != nil {
		t.Fatal(err)
	}
	verifyOperation := adapter.Operation{OperationType: VerifyOperationType, AdapterID: AdapterID,
		TargetID: firstPoint, InputDigest: first.ManifestDigest, ArtifactDigest: first.InventoryDigest,
		SecretReferences: []adapter.SecretReference{{ID: keyID, Consumer: AdapterID}}}
	verifyBinding := adapter.ExactExecutionBinding{PlanID: plan.PlanID, PlanDigest: planDigest,
		RunID: "run-verify", StepID: "step-verify", StateRevision: submission.StateRevision,
		RecoveryEpoch: 0, MaximumExpiresAt: time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339)}
	verifyPassword, err := credentialref.NewValue([]byte("isolated-composition-password"))
	if err != nil {
		t.Fatal(err)
	}
	verificationEffect, err := implementation.ExecuteBoundWithCredentials(ctx, verifyOperation, verifyBinding, []*credentialref.Value{verifyPassword})
	verifyPassword.Close()
	if err != nil || verificationEffect.Status != "succeeded" || verificationEffect.ResultDigest == "" {
		t.Fatalf("fixture verification effect=%#v err=%v restic=%#v", verificationEffect, err, implementation.config.Runner.Observation())
	}
	verificationReceipt, err := backups.GetLocalVerificationByDigest(ctx, verificationEffect.ResultDigest)
	if err != nil || verificationReceipt.Status != "fixture-only" || verificationReceipt.PointID != firstPoint {
		t.Fatalf("fixture verification receipt=%#v err=%v", verificationReceipt, err)
	}
	if verification, err := implementation.Verify(ctx, verifyOperation, verificationEffect); err != nil || !verification.Verified {
		t.Fatalf("exact fixture proof readback=%#v err=%v", verification, err)
	}
	if previous, err := backups.CurrentLocalLastGood(ctx, "standard"); err != nil || previous != "" {
		t.Fatalf("fixture advanced last-good=%q err=%v", previous, err)
	}
	// Current capacity is part of live qualification, not merely point creation.
	// The same sealed policy and points remain unchanged while a bounded file
	// lowers available space below the declared headroom after the first proof.
	liveConfig := implementation.config
	liveConfig.LiveProof = true
	liveConfig.Trust = NewProtectedLocalDependencyTrust()
	live, err := New(liveConfig)
	if err != nil {
		t.Fatal(err)
	}
	livePassword, err := credentialref.NewValue([]byte("isolated-composition-password"))
	if err != nil {
		t.Fatal(err)
	}
	liveBinding := verifyBinding
	liveBinding.RunID, liveBinding.StepID = "run-live-first", "step-live-first"
	firstLive, err := live.ExecuteBoundWithCredentials(ctx, verifyOperation, liveBinding, []*credentialref.Value{livePassword})
	livePassword.Close()
	if err != nil || firstLive.Status != "succeeded" {
		t.Fatalf("first live proof rejected while capacity current: effect=%#v err=%v", firstLive, err)
	}
	priorGood, err := backups.CurrentLocalLastGood(ctx, "standard")
	if err != nil || priorGood == "" {
		t.Fatalf("first live proof did not establish last-good: %q %v", priorGood, err)
	}
	firstGood := priorGood
	second, err := backups.GetPendingRecoveryPoint(ctx, secondPoint)
	if err != nil {
		t.Fatal(err)
	}
	secondOperation := verifyOperation
	secondOperation.TargetID, secondOperation.InputDigest, secondOperation.ArtifactDigest = second.PointID, second.ManifestDigest, second.InventoryDigest
	secondBinding := verifyBinding
	secondBinding.RunID, secondBinding.StepID = "run-live-second", "step-live-second"
	secondPassword, err := credentialref.NewValue([]byte("isolated-composition-password"))
	if err != nil {
		t.Fatal(err)
	}
	secondLive, err := live.ExecuteBoundWithCredentials(ctx, secondOperation, secondBinding, []*credentialref.Value{secondPassword})
	secondPassword.Close()
	if err != nil || secondLive.Status != "succeeded" {
		t.Fatalf("second live proof rejected while capacity current: effect=%#v err=%v", secondLive, err)
	}
	priorGood, err = backups.CurrentLocalLastGood(ctx, "standard")
	if err != nil || priorGood == "" || priorGood == firstGood {
		t.Fatalf("second live proof did not advance last-good: %q %v", priorGood, err)
	}
	custodyPolicy, err := backup.LoadCustodyPolicy(custodyPath)
	if err != nil {
		t.Fatal(err)
	}
	fillerPath := filepath.Join(custodyPolicy.ExchangeRoot, "capacity-reservation")
	filler, err := os.Create(fillerPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Fallocate(int(filler.Fd()), 0, 0, 128<<20); err != nil {
		filler.Close()
		t.Fatalf("reserve disposable capacity: %v", err)
	}
	if err := filler.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := filler.Close(); err != nil {
		t.Fatal(err)
	}
	var constrained unix.Statfs_t
	if err := unix.Statfs(standard, &constrained); err != nil || capacityAdmitted(uint64(constrained.Bavail)*uint64(constrained.Bsize), policy) {
		t.Fatal("capacity fixture did not cross policy headroom")
	}
	secondBinding.RunID, secondBinding.StepID = "run-live-low-capacity", "step-live-low-capacity"
	lowPassword, err := credentialref.NewValue([]byte("isolated-composition-password"))
	if err != nil {
		t.Fatal(err)
	}
	lowEffect, lowErr := live.ExecuteBoundWithCredentials(ctx, secondOperation, secondBinding, []*credentialref.Value{lowPassword})
	lowPassword.Close()
	if lowErr == nil || lowEffect.Status == "succeeded" {
		t.Fatalf("low capacity advanced live proof: effect=%#v err=%v", lowEffect, lowErr)
	}
	if currentGood, err := backups.CurrentLocalLastGood(ctx, "standard"); err != nil || currentGood != priorGood {
		t.Fatalf("low capacity changed prior last-good: before=%q after=%q err=%v", priorGood, currentGood, err)
	}
	status, err := backups.ReadLocalBackupStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	failedAttempt := false
	for _, attempt := range status.Verifications {
		if attempt.RunID != nil && *attempt.RunID == secondBinding.RunID && attempt.PointID == secondPoint && attempt.Status == "failed" {
			failedAttempt = true
		}
	}
	if !failedAttempt {
		t.Fatalf("low capacity did not append failed attempt: %#v", status.Verifications)
	}
	if err := os.Remove(fillerPath); err != nil {
		t.Fatal(err)
	}
	if systemdFixture {
		if err := os.WriteFile(filepath.Join(standard, "config"), []byte("forged"), 0o600); !errors.Is(err, unix.EACCES) {
			t.Fatalf("controller direct repository write err=%v want EACCES", err)
		}
		return
	}
	// A retained repository with an invalid format must fail before the next
	// restic backup and leave both existing pending points intact.
	if err := os.WriteFile(filepath.Join(standard, "config"), []byte(`{"version":1,"id":"old"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	password, err := credentialref.NewValue([]byte("isolated-composition-password"))
	if err != nil {
		t.Fatal(err)
	}
	binding := adapter.ExactExecutionBinding{PlanID: plan.PlanID, PlanDigest: planDigest, RunID: "run-invalid-format", StepID: "step-invalid-format", LeaseID: "executor-invalid-format", StateRevision: submission.StateRevision, RecoveryEpoch: 0, MaximumExpiresAt: time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339)}
	_, err = implementation.ExecuteBoundWithCredentials(ctx, operation, binding, []*credentialref.Value{password})
	password.Close()
	if err == nil {
		t.Fatal("existing repository format v1 reached backup")
	}
	if entries, readErr := os.ReadDir(filepath.Join(standard, "snapshots")); readErr != nil || len(entries) != 2 {
		t.Fatalf("invalid format wrote a new snapshot: entries=%d err=%v", len(entries), readErr)
	}
	if _, err := backups.GetPendingRecoveryPoint(ctx, firstPoint); err != nil {
		t.Fatalf("failed third attempt lost prior point: %v", err)
	}
}

func TestCapacityAdmissionRejectsInt64ForecastOverflow(t *testing.T) {
	policy := generated.BackupPolicy{ExpectedBytes: math.MaxInt64, ExpectedGrowthBytes: math.MaxInt64, MinimumFreeBytes: 2}
	if capacityAdmitted(^uint64(0), policy) {
		t.Fatal("wrapped capacity forecast admitted")
	}
}
