//go:build linux

package server

import (
	"context"
	"database/sql"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/backup"
	"github.com/vegastack/vegastack-labs/internal/backupidentity"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"github.com/vegastack/vegastack-labs/internal/recovery"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/schedule"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/stateexport"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// TestPhase5AcceptanceBuiltProcessRecoveryAndIsolation composes the Phase 5
// surface parity proof with a promoted SQLite authority and the real built
// vsk-labs process. The process must reconcile an ambiguous former-epoch
// effect, survive an ungraceful restart, and retain the recovery, backup and
// audit records that fence the former writer.
func TestPhase5AcceptanceBuiltProcessRecoveryAndIsolation(t *testing.T) {
	t.Run("cli-api-console-parity", runPhase5SurfaceParity)
	t.Run("promoted-authority-process-kill-restart-reconcile", func(t *testing.T) {
		fixture := newPhase5BuiltRecoveryFixture(t)
		fixture.start(t)
		fixture.assertAvailable(t, "before-kill")
		fixture.stop(t, true)
		fixture.start(t)
		fixture.assertAvailable(t, "after-restart")
		fixture.stop(t, false)
		fixture.assertDurableRecovery(t)
	})
}

type phase5BuiltRecoveryFixture struct {
	binaryPath, databasePath, configPath string
	profile                              serverconfig.Profile
	artifacts                            processAuthorityArtifacts
	pointID, verificationID              string
	checkpointID, recoveryPlanID         string
	command                              *exec.Cmd
	done                                 chan error
	serverStdout, serverStderr           *boundedProbeOutput
}

func newPhase5BuiltRecoveryFixture(t *testing.T) *phase5BuiltRecoveryFixture {
	t.Helper()
	binaryPath, runtimeRoot := os.Getenv("VSK_PHASE3_BINARY"), os.Getenv("VSK_PHASE3_RUNTIME_ROOT")
	if !filepath.IsAbs(binaryPath) || !filepath.IsAbs(runtimeRoot) {
		t.Skip("built-executable acceptance runs through the Phase 5 verifier")
	}
	if err := os.MkdirAll(runtimeRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(runtimeRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"control.db", "control.db-wal", "control.db-shm", "control.sock"} {
		if err := os.Remove(filepath.Join(runtimeRoot, name)); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	ctx, now := context.Background(), time.Now().UTC().Truncate(time.Second)
	databasePath := filepath.Join(runtimeRoot, "control.db")
	storeConfig := func(path string, mode store.OpenMode) store.Config {
		return store.Config{DatabasePath: path, Mode: mode, BusyTimeout: 250 * time.Millisecond, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "phase5-test", BuildVersion: "phase5-test", Clock: func() time.Time { return now }}
	}
	authority, err := store.Open(ctx, storeConfig(databasePath, store.InitializeNew))
	if err != nil {
		t.Fatal(err)
	}
	prior, err := authority.CurrentAuthority(ctx)
	if err != nil {
		t.Fatal(err)
	}
	repositoryID, encryptionID, recoveryID := backupidentity.StandardRepository, "enc-a", "recovery-phase5"
	policy := generated.BackupPolicy{
		Schema: generated.SchemaIDBackupPolicy, SchemaVersion: "1.2.0", PolicyID: "policy-a",
		OwnerID: "owner-phase5", SourceID: backupidentity.ControlDatabaseSource,
		SourceSelectors: []string{backupidentity.ControlDatabaseSelector}, ConsistencyHookID: backup.SQLiteOnlineHookID,
		RepositoryID: &repositoryID, RepositoryClass: "standard", ScheduleIntent: "manual",
		ExpectedBytes: 1 << 20, ExpectedGrowthBytes: 1 << 20, MinimumFreeBytes: 1,
		EncryptionKeyReferenceID: &encryptionID, RecoveryKeyReferenceID: &recoveryID,
		RetentionDays: 7, RestoreTargetID: "control-database", Dependencies: []generated.BackupDependency{},
		FunctionalTestRequired: true, FullPayloadIntervalHours: 24, FunctionalTestIntervalHours: 24,
		RecoveryEpoch: 0, Revision: 1,
	}
	_, sum, err := stateexport.CanonicalJSON(policy)
	if err != nil {
		t.Fatal(err)
	}
	backups := store.NewBackupRepository(authority)
	submission, err := backups.CreateBackupPolicyDraft(ctx, generated.BackupPolicyDraftRequest{
		Schema: generated.SchemaIDBackupPolicyDraftRequest, SchemaVersion: "1.1.0",
		ExpectedStateRevision: 0, RecoveryEpoch: 0, TargetDigest: "sha256:" + hex.EncodeToString(sum[:]),
		IdempotencyKey: "phase5-prior-good-policy", Policy: policy,
	}, processAttribution("human-phase5"))
	if err != nil {
		t.Fatal(err)
	}
	point, verification := seedAcceptancePointAtRevision(t, ctx, backups, submission.PolicyDigest, "point-phase5-prior-good", 0, now, 1, repositoryID, "standard")
	if err := backups.AdvanceLocalLastGood(ctx, verification, store.RevisionToken{StateRevision: 1, RecoveryEpoch: 0}, ""); err != nil {
		t.Fatal(err)
	}
	chain, err := authority.ChainRange(ctx, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := store.NewPlanRepository(authority).CurrentRevision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	checkpointID := "checkpoint-phase5-prior-good"
	checkpoint := generated.AuditCheckpoint{
		Schema: generated.SchemaIDAuditCheckpoint, SchemaVersion: "1.1.0", CheckpointID: checkpointID,
		FirstEventID: 1, LastEventID: 1, ChainDigest: string(chain.RangeDigest), InstanceID: chain.Links[0].InstanceID,
		FirstSegmentSequence: chain.Links[0].SegmentSequence, LastSegmentSequence: chain.Links[0].SegmentSequence,
		SignerReferenceID: "signer-phase5", SignerMaterialVersion: "version-phase5", Status: "pending",
		ReasonCode: "awaiting-provider", SourceKind: "local", ProofClass: "fixture", VerificationStatus: "pending", RecoveryEpoch: 0,
	}
	if _, err := authority.CreatePendingCheckpoint(ctx, store.CheckpointCreateRequest{
		Checkpoint: checkpoint, ExactPath: "audit-anchor/" + checkpointID + ".json.enc", Expected: revision,
		KeyDigest:     audit.Fingerprint(canaryAcceptanceDigest("phase5-checkpoint-key")),
		RequestDigest: audit.Fingerprint(canaryAcceptanceDigest("phase5-checkpoint-request")),
		Attribution:   processAttribution("human-phase5"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := authority.Close(); err != nil {
		t.Fatal(err)
	}
	artifacts := processOldAuthorityArtifacts(t)
	seedProcessOldAuthorityArtifacts(t, databasePath, artifacts)
	formatted := now.Format(time.RFC3339Nano)
	if err := updateBrowserIntegrationDatabase(databasePath, `INSERT INTO read_principals(principal_id,status,grant_revision,created_at,updated_at) VALUES('principal.phase5','active',1,?,?)`, formatted, formatted); err != nil {
		t.Fatal(err)
	}
	if err := updateBrowserIntegrationDatabase(databasePath, `INSERT INTO read_grants(principal_id,capability,resource_kind,resource_id,grant_revision,status,created_at,updated_at) VALUES('principal.phase5','control.health.read','control','health',1,'active',?,?)`, formatted, formatted); err != nil {
		t.Fatal(err)
	}
	_, _, binding, _ := canaryAcceptanceBundle(t, prior, point)
	opener := func(ctx context.Context, path string) (*store.Store, error) {
		return store.Open(ctx, storeConfig(path, store.OpenExisting))
	}
	if err := (recovery.StoreCandidateAuthority{Open: opener}).PrepareRecoveredAuthority(ctx, databasePath, binding, recovery.AuditContinuity{IndependentCheckpointDigest: canaryAcceptanceDigest("phase5-prior-checkpoint"), DecisionDigest: binding.AuditDecisionDigest}); err != nil {
		t.Fatal(err)
	}
	promoted, err := opener(ctx, databasePath)
	if err != nil {
		t.Fatal(err)
	}
	health, err := promoted.Health(ctx)
	if err != nil || !health.RecoveryPending || health.MutationEnabled || health.Revision.RecoveryEpoch != binding.NextRecoveryEpoch {
		t.Fatalf("promoted authority health=%#v err=%v", health, err)
	}
	assertProcessOldAuthorityDenied(t, promoted, artifacts)
	if err := promoted.EnableRecoveredAuthority(ctx, binding.NewInstanceID, binding.NextRecoveryEpoch, health.Revision.StateRevision, canaryAcceptanceDigest("phase5-canary-complete")); err != nil {
		t.Fatal(err)
	}
	if err := promoted.Close(); err != nil {
		t.Fatal(err)
	}
	exportRoot := filepath.Join(runtimeRoot, "exports")
	if err := os.MkdirAll(exportRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	profileJSON := generated.ServerProfile{
		Schema: generated.SchemaIDServerProfile, SchemaVersion: "1.3.0",
		SocketPath: filepath.Join(runtimeRoot, "control.sock"), SocketOwnerUID: int64(os.Geteuid()), SocketMode: "0600",
		ShutdownGraceSeconds: 5, InventoryExportRoot: exportRoot,
		PrincipalBindings: []generated.LocalPrincipalBinding{{UID: int64(os.Geteuid()), PrincipalID: "principal.phase5"}},
	}
	configPath := filepath.Join(runtimeRoot, "server-profile.json")
	writeProtectedJSON(t, configPath, profileJSON)
	profile, err := serverconfig.NewLoader(uint32(os.Geteuid())).Load(ctx, configPath)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &phase5BuiltRecoveryFixture{
		binaryPath: binaryPath, databasePath: databasePath, configPath: configPath, profile: profile,
		artifacts: artifacts, pointID: point.PointID, verificationID: verification.VerificationID,
		checkpointID: checkpointID, recoveryPlanID: binding.PlanID,
	}
	t.Cleanup(func() {
		if fixture.command != nil && fixture.command.Process != nil {
			_ = fixture.command.Process.Kill()
			select {
			case <-fixture.done:
			case <-time.After(time.Second):
			}
		}
	})
	return fixture
}

func (fixture *phase5BuiltRecoveryFixture) start(t *testing.T) {
	t.Helper()
	fixture.command = exec.Command(fixture.binaryPath, "server", "run", "--config", fixture.configPath, "--output", "json")
	fixture.serverStdout, fixture.serverStderr = &boundedProbeOutput{limit: 16 * 1024}, &boundedProbeOutput{limit: 512}
	fixture.command.Stdout, fixture.command.Stderr = fixture.serverStdout, fixture.serverStderr
	fixture.done = make(chan error, 1)
	if err := fixture.command.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { fixture.done <- fixture.command.Wait() }()
}

func (fixture *phase5BuiltRecoveryFixture) stop(t *testing.T, kill bool) {
	t.Helper()
	if fixture.command == nil {
		return
	}
	var signalErr error
	if kill {
		signalErr = fixture.command.Process.Kill()
	} else {
		signalErr = fixture.command.Process.Signal(os.Interrupt)
	}
	if signalErr != nil {
		t.Fatal(signalErr)
	}
	select {
	case err := <-fixture.done:
		if kill && err == nil {
			t.Fatal("killed server reported a graceful exit")
		}
		if !kill && err != nil {
			t.Fatalf("server shutdown: %v", err)
		}
	case <-time.After(7 * time.Second):
		_ = fixture.command.Process.Kill()
		t.Fatal("built server did not stop")
	}
	fixture.command = nil
}

func (fixture *phase5BuiltRecoveryFixture) assertAvailable(t *testing.T, stage string) {
	t.Helper()
	factory := result.NewFactory(result.BuildInfo{ToolVersion: "phase5-test", ReleaseBuildID: "phase5-test"}, func() (string, error) {
		return "request-phase5-built-process", nil
	})
	client := localapi.NewClient(factory)
	var lastErr error
	for deadline := time.Now().Add(7 * time.Second); time.Now().Before(deadline); {
		status, err := client.Status(context.Background(), fixture.profile)
		lastErr = err
		if err == nil && status.ExitCode == 0 && status.Status.State == string(StateReady) && status.Status.ReadAvailable && !status.Status.MutationAvailable && status.Status.RecoveryEpoch == 1 {
			return
		}
		select {
		case runErr := <-fixture.done:
			fixture.done <- runErr
			t.Fatalf("built server exited at %s: %v stdout=%q stderr=%q", stage, runErr, fixture.serverStdout.Bytes(), fixture.serverStderr.Bytes())
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("built server unavailable at %s: %v stdout=%q stderr=%q", stage, lastErr, fixture.serverStdout.Bytes(), fixture.serverStderr.Bytes())
}

func (fixture *phase5BuiltRecoveryFixture) assertDurableRecovery(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	authority, err := store.Open(ctx, store.Config{DatabasePath: fixture.databasePath, Mode: store.OpenExisting, BusyTimeout: 250 * time.Millisecond, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "phase5-test", BuildVersion: "phase5-test"})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	health, err := authority.Health(ctx)
	if err != nil || health.RecoveryPending || !health.MutationEnabled || health.Revision.RecoveryEpoch != 1 {
		t.Fatalf("restarted authority health=%#v err=%v", health, err)
	}
	run, err := store.NewRunRepository(authority).Get(ctx, fixture.artifacts.Run.RunID)
	if err != nil || run.Status != "partial" || run.VerificationStatus != "incomplete" || run.RollbackStatus != "required" || len(run.Steps) != 1 || run.Steps[0].Status != "partial" || run.Steps[0].EffectState != "effect-unknown" {
		t.Fatalf("reconciled former run=%#v err=%v", run, err)
	}
	former := store.RevisionToken{StateRevision: health.Revision.StateRevision, RecoveryEpoch: 0}
	if _, err := authority.WriteIntent(ctx, &former, func(store.IntentTx) error { return nil }); store.Code(err) != generated.ErrorCodeRecoveryEpochMismatch {
		t.Fatalf("former writer code=%q", store.Code(err))
	}
	database, err := sql.Open("sqlite3", "file:"+fixture.databasePath+"?mode=rw")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	assertCount := func(name, query string, args ...any) {
		t.Helper()
		var count int
		if err := database.QueryRow(query, args...).Scan(&count); err != nil || count != 1 {
			t.Fatalf("%s count=%d err=%v", name, count, err)
		}
	}
	assertCount("prior last-good", `SELECT COUNT(1) FROM backup_local_last_good WHERE point_id=? AND verification_id=? AND recovery_epoch=0`, fixture.pointID, fixture.verificationID)
	assertCount("prior audit checkpoint", `SELECT COUNT(1) FROM audit_checkpoints WHERE checkpoint_id=? AND recovery_epoch=0`, fixture.checkpointID)
	assertCount("promoted restore authority", `SELECT COUNT(1) FROM recovery_authority_journal WHERE plan_id=? AND transition='promoted' AND recovery_epoch=1`, fixture.recoveryPlanID)
	assertCount("verified restore authority", `SELECT COUNT(1) FROM recovery_authority_journal WHERE plan_id=? AND transition='verified' AND recovery_epoch=1`, fixture.recoveryPlanID)
	assertCount("released former lease", `SELECT COUNT(1) FROM target_execution_leases WHERE lease_id=? AND status='released'`, fixture.artifacts.Lease.LeaseID)

	now := time.Now().UTC().Truncate(time.Second)
	policy := generated.ScheduledJobPolicy{
		Schema: generated.SchemaIDScheduledJobPolicy, SchemaVersion: "1.1.0",
		PolicyID: "schedule-phase5-provider-outage", Revision: 1,
		DeclarationID: "declaration-phase5-provider-outage", DeclarationRevision: 1,
		ActionKind: "audit-checkpoint-export", OperationType: "audit.checkpoint.anchor", AdapterID: "core.audit",
		ExactSourceIDs: []string{fixture.checkpointID}, ExactSubjectIDs: []string{"audit-chain"},
		ExactTargetIDs: []string{"instance-replacement-process"}, MaximumWork: 1,
		CredentialReferenceIDs: []string{"signer-phase5"}, GrantRevision: 1,
		StateRevision: health.Revision.StateRevision, RecoveryEpoch: health.Revision.RecoveryEpoch,
		PolicyVersion: "1.0.0", RetentionRuleDigest: canaryAcceptanceDigest("phase5-outage-policy"),
		AnchorAt: now.Add(-time.Hour).Format(time.RFC3339), IntervalSeconds: 3600, WindowSeconds: 1800,
		CatchUp: "latest", Concurrency: "forbid", MaxAttempts: 1, InitialBackoffSeconds: 1, MaximumBackoffSeconds: 1,
		ExpiresAt: now.Add(24 * time.Hour).Format(time.RFC3339), Enabled: true,
	}
	canonical, policyDigest, err := schedule.CanonicalPolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO scheduled_policy_drafts(draft_id,policy_id,policy_revision,canonical_json,policy_digest,created_by_human_id,state_revision,recovery_epoch,created_at) VALUES('draft-phase5-provider-outage',?,1,?,?,'human-phase5',?,?,?)`, policy.PolicyID, string(canonical), policyDigest, policy.StateRevision, policy.RecoveryEpoch, now.Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO scheduled_policy_activations(activation_id,draft_id,policy_id,policy_revision,status,approval_plan_id,approval_plan_digest,acknowledgement_id,approved_by_human_id,state_revision,recovery_epoch,activated_at) VALUES('activation-phase5-provider-outage','draft-phase5-provider-outage',?,1,'active','plan-provider-outage',?,'ack-provider-outage','human-phase5',?,?,?)`, policy.PolicyID, canaryAcceptanceDigest("phase5-outage-plan"), policy.StateRevision, policy.RecoveryEpoch, now.Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	policies := store.NewScheduleRepository(authority)
	backups := store.NewBackupRepository(authority)
	reader := schedulePrerequisiteReader{
		authority: authority, policies: policies, gates: store.NewGateRepository(authority), backups: backups,
		offsite: recovery.SQLOffsiteSourceReader{Local: backups, Offsite: store.NewOffsiteRepository(authority)},
		clock:   func() time.Time { return now }, backupReady: true, auditReady: false,
	}
	requirements := schedule.Requirements(policy)
	statuses, err := reader.Current(ctx, requirements)
	if err != nil {
		t.Fatal(err)
	}
	if err := schedule.RequireCurrent(requirements, statuses, now); err == nil {
		t.Fatalf("unavailable audit provider admitted: statuses=%+v", statuses)
	}
	if status, err := backups.ReadLocalBackupStatus(ctx); err != nil || status.RecoveryEpoch != 1 {
		t.Fatalf("local backup inspection during provider outage=%#v err=%v", status, err)
	}
	assertCount("prior last-good after provider outage", `SELECT COUNT(1) FROM backup_local_last_good WHERE point_id=? AND verification_id=? AND recovery_epoch=0`, fixture.pointID, fixture.verificationID)
	assertCount("prior audit checkpoint after provider outage", `SELECT COUNT(1) FROM audit_checkpoints WHERE checkpoint_id=? AND recovery_epoch=0`, fixture.checkpointID)
}
