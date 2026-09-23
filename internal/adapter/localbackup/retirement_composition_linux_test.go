//go:build linux

package localbackup

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/adapter/localretention"
	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/backup"
	"github.com/vegastack/vegastack-labs/internal/backupidentity"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	planengine "github.com/vegastack/vegastack-labs/internal/plan"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/stateexport"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type retirementCompositionAuthorizer struct{}

func (retirementCompositionAuthorizer) Authorize(_ context.Context, principal identity.Principal, request authorization.Request) (authorization.Decision, error) {
	decision := authorization.Decision{Allowed: true, PrincipalID: principal.ID, Action: request.Action, Target: request.Target,
		ReasonCode: authorization.ReasonAllowed, GrantRevision: 1,
		Scope: authorization.EffectiveScope{PrincipalID: principal.ID, Action: request.Action, Capability: request.Target.Capability,
			ResourceKind: request.Target.ResourceKind, ResourceID: request.Target.ResourceID, Role: authorization.RoleInfrastructureAdmin, GrantRevision: 1}}
	if request.Plan != nil {
		branch := authorization.Branch(request.Plan.AuthorizationBranch)
		decision.Branch, decision.PlanDigest = &branch, request.Plan.PlanDigest
		decision.StateRevision, decision.RecoveryEpoch = request.Plan.Binding.StateRevision, request.Plan.Binding.RecoveryEpoch
		decision.Scope.StateRevision, decision.Scope.RecoveryEpoch = decision.StateRevision, decision.RecoveryEpoch
	}
	return decision, nil
}

type retirementCompositionPlanReader struct{ plans *planengine.Service }

func (reader retirementCompositionPlanReader) Get(ctx context.Context, id string) (generated.Plan, error) {
	value, err := reader.plans.Get(ctx, id)
	return value.Plan, err
}
func (reader retirementCompositionPlanReader) ValidateCurrent(ctx context.Context, value generated.Plan) error {
	return reader.plans.ValidateCurrent(ctx, value)
}

type retirementCompositionSecretGate struct{ databasePath string }

func (gate retirementCompositionSecretGate) VerifySecretStep(ctx context.Context, plan generated.Plan, operation generated.PlanOperation) error {
	db, err := sql.Open("sqlite3", "file:"+gate.databasePath+"?mode=ro")
	if err != nil {
		return err
	}
	defer db.Close()
	var count int
	err = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM plan_run_steps s JOIN plan_runs r ON r.run_id=s.run_id JOIN target_execution_leases l ON l.lease_id=s.active_lease_id
		WHERE r.plan_id=? AND r.plan_digest=? AND r.status='running' AND s.operation_id=? AND s.status='running' AND s.effect_state='intent-recorded' AND l.status='active'`, plan.PlanID, plan.PlanDigest, operation.OperationID).Scan(&count)
	if err != nil || count != 1 {
		return errors.New("retirement composition requires one exact running lease")
	}
	return nil
}

type retirementCompositionResolver struct{ password []byte }

func (resolver retirementCompositionResolver) Resolve(context.Context, credentialref.StepBinding) (*credentialref.Value, error) {
	return credentialref.NewValue(append([]byte(nil), resolver.password...))
}

type retirementCompositionProfiles struct{ revision int64 }

func (profiles retirementCompositionProfiles) GetAppliedProfileScope(context.Context) (store.GateAppliedProfile, error) {
	return store.GateAppliedProfile{ProfileID: "profile-retirement-composition", ProfileVersion: "1.0.0", PolicyID: "policy-retirement-composition", PolicyVersion: "1.0.0",
		Capabilities: []string{"credential.native.read"}, StateRevision: profiles.revision, RecoveryEpoch: 0}, nil
}

type retirementCompositionRetentionAdapter struct {
	t     *testing.T
	inner *localretention.Adapter
}

func (wrapper *retirementCompositionRetentionAdapter) Execute(ctx context.Context, operation adapter.Operation) (adapter.Effect, error) {
	return wrapper.inner.Execute(ctx, operation)
}

func (wrapper *retirementCompositionRetentionAdapter) Verify(ctx context.Context, operation adapter.Operation, effect adapter.Effect) (adapter.Verification, error) {
	return wrapper.inner.Verify(ctx, operation, effect)
}

func (wrapper *retirementCompositionRetentionAdapter) ExecuteBoundWithCredentials(ctx context.Context, operation adapter.Operation, binding adapter.ExactExecutionBinding, values []*credentialref.Value) (adapter.Effect, error) {
	effect, err := wrapper.inner.ExecuteBoundWithCredentials(ctx, operation, binding, values)
	if err != nil {
		wrapper.t.Logf("local retirement adapter failed: %v", err)
	}
	return effect, err
}

type retirementCompositionFixture struct {
	t                *testing.T
	ctx              context.Context
	authority        *store.Store
	databasePath     string
	clock            func() time.Time
	profile          *serverconfig.LocalBackup
	backups          *store.BackupRepository
	retirements      *store.LocalRetirementRepository
	inspector        store.RestoredSQLiteInspector
	backupAdapter    *Adapter
	backupPlan       generated.Plan
	password         []byte
	principal        identity.Principal
	firstPoint       store.PendingRecoveryPoint
	survivorPoint    store.PendingRecoveryPoint
	nextPoint        store.PendingRecoveryPoint
	policySubmission generated.BackupPolicyDraftSubmission
}

// TestLocalRetirementPublicComposition is the vertical acceptance for the
// destructive local-retirement path. It runs only in the existing disposable
// systemd/ext4 custody lane and uses the official pinned restic binary.
func TestLocalRetirementPublicComposition(t *testing.T) {
	if os.Getenv("VSK_CUSTODY_SYSTEMD_FIXTURE") != "1" {
		t.Skip("production custody composition requires the disposable systemd fixture")
	}
	if os.Getenv("VSK_RESTIC_0191_BINARY") == "" {
		t.Skip("official pinned restic 0.19.1 binary not provided")
	}
	if os.Geteuid() != 21164 {
		t.Fatalf("systemd fixture controller uid=%d want=21164", os.Geteuid())
	}
	fixture := newRetirementCompositionFixture(t)
	fixture.createAndVerifyPoints()
	fixture.ageFirstPoint()
	fixture.activatePublicRetentionLocks()
	fixture.runPublicRetirement("retirement", fixture.firstPoint, fixture.survivorPoint, true)
	fixture.verifySuccessorThroughLocalBackup(fixture.survivorPoint, "first")
	fixture.nextPoint = fixture.createAndVerifyPostSuccessorPoint()
	fixture.assertSecondDraftUsesSuccessorSource()
	fixture.agePoint(fixture.survivorPoint, fixture.nextPoint)
	fixture.runPublicRetirement("retirement-second", fixture.survivorPoint, fixture.nextPoint, false)
	fixture.verifySuccessorThroughLocalBackup(fixture.nextPoint, "second")
}

func newRetirementCompositionFixture(t *testing.T) *retirementCompositionFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	t.Cleanup(cancel)
	clock := func() time.Time { return time.Now().UTC() }
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatalf("fixture temp permissions: %v", err)
	}
	databasePath := filepath.Join(directory, "control.db")
	authority, err := store.Open(ctx, store.Config{DatabasePath: databasePath, Mode: store.InitializeNew, ExpectedUID: uint32(os.Geteuid()), BusyTimeout: 5 * time.Second, ToolVersion: "retirement-composition", BuildVersion: "retirement-composition", Clock: clock})
	if err != nil {
		t.Fatalf("fixture store: %v", err)
	}
	t.Cleanup(func() { _ = authority.Close() })
	policy, err := backup.LoadCustodyPolicy(backup.CustodyPolicyPath)
	if err != nil {
		t.Fatalf("fixture custody policy: %v", err)
	}
	binary := os.Getenv("VSK_RESTIC_0191_BINARY")
	profile := &serverconfig.LocalBackup{StandardRoot: policy.StandardRoot, CriticalRoot: policy.CriticalRoot, ResticBinaryPath: binary, CustodyPolicyPath: backup.CustodyPolicyPath,
		SourceID: backupidentity.ControlDatabaseSource, StandardRepositoryID: backupidentity.StandardRepository, CriticalRepositoryID: backupidentity.CriticalRepository}
	backups := store.NewBackupRepository(authority)
	snapshots, err := store.NewOnlineSnapshotSource(authority)
	if err != nil {
		t.Fatalf("fixture snapshot source: %v", err)
	}
	inspector, err := store.NewRestoredSQLiteInspector(authority)
	if err != nil {
		t.Fatalf("fixture inspector: %v", err)
	}
	var filesystem unix.Statfs_t
	if err := unix.Statfs(policy.StandardRoot, &filesystem); err != nil {
		t.Fatalf("fixture repository capacity: %v", err)
	}
	free := uint64(filesystem.Bavail) * uint64(filesystem.Bsize)
	if free < 256<<20 || free > uint64(^uint64(0)>>1) {
		t.Skip("disposable filesystem lacks bounded capacity headroom")
	}
	repositoryID, keyID, recoveryID := backupidentity.StandardRepository, "retirement-key", "retirement-recovery"
	backupPolicy := generated.BackupPolicy{Schema: generated.SchemaIDBackupPolicy, SchemaVersion: "1.2.0", PolicyID: "policy-retirement-composition", OwnerID: "owner-retirement-composition",
		SourceID: backupidentity.ControlDatabaseSource, SourceSelectors: []string{backupidentity.ControlDatabaseSelector}, ConsistencyHookID: backup.SQLiteOnlineHookID,
		RepositoryID: &repositoryID, RepositoryClass: "standard", ScheduleIntent: "manual", ExpectedBytes: 4 << 20, ExpectedGrowthBytes: 4 << 20,
		MinimumFreeBytes: int64(free) - (96 << 20), EncryptionKeyReferenceID: &keyID, RecoveryKeyReferenceID: &recoveryID, RetentionDays: 7,
		RestoreTargetID: "isolated-retirement-composition", Dependencies: []generated.BackupDependency{{DependencyID: "binary-restic", Kind: "binary", Digest: pinnedResticDigest()}},
		FunctionalTestRequired: true, FullPayloadIntervalHours: 24, FunctionalTestIntervalHours: 168, RecoveryEpoch: 0, Revision: 1}
	_, sum, err := stateexport.CanonicalJSON(backupPolicy)
	if err != nil {
		t.Fatalf("fixture policy digest: %v", err)
	}
	submission, err := backups.CreateBackupPolicyDraft(ctx, generated.BackupPolicyDraftRequest{Schema: generated.SchemaIDBackupPolicyDraftRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: 0, RecoveryEpoch: 0,
		TargetDigest: "sha256:" + hex.EncodeToString(sum[:]), IdempotencyKey: "retirement-composition-policy", Policy: backupPolicy}, audit.Attribution{AuthenticatedPrincipalID: "operator-retirement-composition", AuthenticatedPrincipalMethod: identity.LocalOSPeerMethod})
	if err != nil {
		t.Fatalf("fixture policy draft: %v", err)
	}
	planDigest := compositionDigest("backup-plan")
	plan := generated.Plan{PlanID: "plan-retirement-backup", PlanDigest: planDigest, Binding: generated.PlanBinding{StateRevision: submission.StateRevision, RecoveryEpoch: 0},
		Extensions: []generated.ContractExtension{{Name: "x-backup-policy", ValueDigest: submission.PolicyDigest}}}
	implementation, err := New(Config{LocalBackup: profile, ExpectedUID: policy.ControllerUID, Backups: backups, Snapshots: snapshots, Inspector: inspector,
		Trust: NewProtectedLocalDependencyTrust(), LiveProof: true, Plans: fixedPlanSource{plan}, Hooks: backup.DefaultHookRegistry(), Runner: backup.NewResticRunner(), Clock: clock})
	if err != nil {
		t.Fatalf("fixture backup adapter: %v", err)
	}
	fixture := &retirementCompositionFixture{t: t, ctx: ctx, authority: authority, databasePath: databasePath, clock: clock, profile: profile, backups: backups,
		retirements: store.NewLocalRetirementRepository(authority), inspector: inspector, backupAdapter: implementation, backupPlan: plan,
		password: []byte("isolated-retirement-composition-password"), principal: identity.Principal{ID: "operator-retirement-composition", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}, policySubmission: submission}
	return fixture
}

func (fixture *retirementCompositionFixture) createAndVerifyPoints() {
	t := fixture.t
	keyID := "retirement-key"
	var points []store.PendingRecoveryPoint
	for index := 0; index < 2; index++ {
		password, err := credentialref.NewValue(fixture.password)
		if err != nil {
			t.Fatal(err)
		}
		operation := adapter.Operation{OperationType: OperationType, AdapterID: AdapterID, TargetID: "control-retirement-composition", SecretReferences: []adapter.SecretReference{{ID: keyID, Consumer: AdapterID}}}
		binding := adapter.ExactExecutionBinding{PlanID: fixture.backupPlan.PlanID, PlanDigest: fixture.backupPlan.PlanDigest, RunID: "run-retirement-backup-" + string(rune('1'+index)),
			StepID: "step-retirement-backup-" + string(rune('1'+index)), LeaseID: "lease-retirement-backup-" + string(rune('1'+index)), StateRevision: fixture.policySubmission.StateRevision,
			RecoveryEpoch: 0, MaximumExpiresAt: fixture.clock().Add(5 * time.Minute).Format(time.RFC3339)}
		effect, runErr := fixture.backupAdapter.ExecuteBoundWithCredentials(fixture.ctx, operation, binding, []*credentialref.Value{password})
		password.Close()
		if runErr != nil || effect.PendingPointID == nil {
			t.Fatalf("create point %d: effect=%#v err=%v", index, effect, runErr)
		}
		point, err := fixture.backups.GetPendingRecoveryPoint(fixture.ctx, *effect.PendingPointID)
		if err != nil {
			t.Fatal(err)
		}
		verify := adapter.Operation{OperationType: VerifyOperationType, AdapterID: AdapterID, TargetID: point.PointID, InputDigest: point.ManifestDigest, ArtifactDigest: point.InventoryDigest,
			SecretReferences: []adapter.SecretReference{{ID: keyID, Consumer: AdapterID}}}
		password, err = credentialref.NewValue(fixture.password)
		if err != nil {
			t.Fatal(err)
		}
		binding.RunID, binding.StepID, binding.LeaseID = "run-retirement-verify-"+string(rune('1'+index)), "step-retirement-verify-"+string(rune('1'+index)), "lease-retirement-verify-"+string(rune('1'+index))
		verified, verifyErr := fixture.backupAdapter.ExecuteBoundWithCredentials(fixture.ctx, verify, binding, []*credentialref.Value{password})
		password.Close()
		if verifyErr != nil || verified.Status != "succeeded" {
			t.Fatalf("verify point %d: effect=%#v err=%v", index, verified, verifyErr)
		}
		points = append(points, point)
	}
	fixture.firstPoint, fixture.survivorPoint = points[0], points[1]
}

func (fixture *retirementCompositionFixture) ageFirstPoint() {
	fixture.agePoint(fixture.firstPoint, fixture.survivorPoint)
}

func (fixture *retirementCompositionFixture) agePoint(point, newer store.PendingRecoveryPoint) {
	fixture.t.Helper()
	db, err := sql.Open("sqlite3", "file:"+fixture.databasePath+"?_busy_timeout=5000")
	if err != nil {
		fixture.t.Fatal(err)
	}
	defer db.Close()
	tx, err := db.BeginTx(fixture.ctx, nil)
	if err != nil {
		fixture.t.Fatal(err)
	}
	defer tx.Rollback()
	// Production recovery points are append-only. This fixture-only rewrite is
	// isolated to created_at so retention sees one aged, already verified point.
	if _, err := tx.ExecContext(fixture.ctx, `DROP TRIGGER recovery_points_no_update`); err != nil {
		fixture.t.Fatal(err)
	}
	aged := fixture.clock().Add(-8 * 24 * time.Hour).Format(time.RFC3339)
	result, err := tx.ExecContext(fixture.ctx, `UPDATE recovery_points SET created_at=? WHERE point_id=?`, aged, point.PointID)
	if err != nil {
		fixture.t.Fatal(err)
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		fixture.t.Fatalf("age first point: changed=%d err=%v", changed, err)
	}
	if _, err := tx.ExecContext(fixture.ctx, `CREATE TRIGGER recovery_points_no_update BEFORE UPDATE ON recovery_points BEGIN SELECT RAISE(ABORT, 'recovery points are append-only'); END`); err != nil {
		fixture.t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		fixture.t.Fatal(err)
	}
	var firstRaw, survivorRaw string
	if err := db.QueryRowContext(fixture.ctx, `SELECT created_at FROM recovery_points WHERE point_id=?`, point.PointID).Scan(&firstRaw); err != nil {
		fixture.t.Fatal(err)
	}
	if err := db.QueryRowContext(fixture.ctx, `SELECT created_at FROM recovery_points WHERE point_id=?`, newer.PointID).Scan(&survivorRaw); err != nil {
		fixture.t.Fatal(err)
	}
	first, firstErr := time.Parse(time.RFC3339, firstRaw)
	survivor, survivorErr := time.Parse(time.RFC3339, survivorRaw)
	if firstErr != nil || survivorErr != nil || !first.Before(survivor.Add(-7*24*time.Hour)) {
		fixture.t.Fatalf("point fixture is not older than the retirement window: first=%s survivor=%s", firstRaw, survivorRaw)
	}
}

func (fixture *retirementCompositionFixture) declarations() *change.Service {
	service, err := change.NewService(store.NewDeclarationRepository(fixture.authority), fixture.clock)
	if err != nil {
		fixture.t.Fatal(err)
	}
	return service
}

func (fixture *retirementCompositionFixture) activatePublicRetentionLocks() {
	t := fixture.t
	current, err := store.NewPlanRepository(fixture.authority).CurrentRevision(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	catalog := generated.LocalRetentionLockCatalog{Schema: generated.SchemaIDLocalRetentionLockCatalog, SchemaVersion: "1.0.0", RepositoryID: backupidentity.StandardRepository,
		RepositoryClass: "standard", SourceCoverageDigest: store.LocalPromiseSourceCoverageDigest(), RecoveryEpoch: 0, Revision: 2, Complete: true, Locks: []generated.BackupRetentionLock{}}
	storeCatalog := store.LocalRetentionLockCatalog{Schema: catalog.Schema, SchemaVersion: catalog.SchemaVersion, RepositoryID: catalog.RepositoryID, RepositoryClass: catalog.RepositoryClass,
		SourceCoverageDigest: catalog.SourceCoverageDigest, RecoveryEpoch: catalog.RecoveryEpoch, Revision: catalog.Revision, Complete: catalog.Complete, Locks: []store.LocalRetentionLock{}}
	_, digest, err := store.CanonicalLocalRetentionLockCatalog(storeCatalog)
	if err != nil {
		t.Fatal(err)
	}
	service, err := api.NewRetentionLockDraftService(fixture.retirements, store.NewPlanRepository(fixture.authority), fixture.declarations(), retirementCompositionAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	submission, err := service.CreateDraft(fixture.ctx, generated.BackupRetentionLockDraftRequest{Schema: generated.SchemaIDBackupRetentionLockDraftRequest, SchemaVersion: "1.1.0",
		ExpectedStateRevision: current.StateRevision, RecoveryEpoch: 0, TargetDigest: digest, IdempotencyKey: "retirement-composition-lock", Catalog: catalog}, fixture.principal)
	if err != nil {
		t.Fatal(err)
	}
	core, err := runengine.NewCoreRetentionLockEffect(fixture.retirements, store.NewAcknowledgementRepository(fixture.authority))
	if err != nil {
		t.Fatal(err)
	}
	result := fixture.applyChange(submission.ChangeID, submission.OperationID, "lock", adapter.NewRegistry(), core, nil)
	if result.Status != "succeeded" {
		t.Fatalf("retention lock run=%#v", result)
	}
	locks, err := fixture.retirements.CurrentAppliedLocalRetentionLocks(fixture.ctx, "standard", 0)
	if err != nil || locks.CatalogDigest != digest {
		t.Fatalf("applied retention locks=%#v err=%v", locks, err)
	}
}

func (fixture *retirementCompositionFixture) runPublicRetirement(key string, target, survivor store.PendingRecoveryPoint, seedCredential bool) {
	t := fixture.t
	revisions := store.NewPlanRepository(fixture.authority)
	current, err := revisions.CurrentRevision(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	targetDigest, err := store.LocalRepositoryPlanTargetDigest(backupidentity.StandardRepository)
	if err != nil {
		t.Fatal(err)
	}
	credentials := store.NewCredentialRepository(fixture.authority)
	service, err := api.NewRetirementDraftService(fixture.retirements, credentials, revisions, fixture.declarations(), retirementCompositionAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	submission, err := service.CreateDraft(fixture.ctx, generated.BackupRetirementDraftRequest{Schema: generated.SchemaIDBackupRetirementDraftRequest, SchemaVersion: "1.1.0",
		ExpectedStateRevision: current.StateRevision, RecoveryEpoch: 0, TargetDigest: targetDigest, IdempotencyKey: "retirement-composition-" + key, RepositoryClass: "standard",
		ReferenceID: "reference-retirement-composition", ResolverID: "native-systemd", MaterialVersion: "version-retirement-composition"}, fixture.principal)
	if err != nil {
		t.Fatal(err)
	}
	if len(submission.TargetPointIDs) != 1 || submission.TargetPointIDs[0] != target.PointID || len(submission.SurvivorPointIDs) != 1 || submission.SurvivorPointIDs[0] != survivor.PointID {
		t.Fatalf("server-derived selection=%#v", submission)
	}
	if seedCredential {
		fixture.seedActiveRetirementReference(submission.StateRevision)
	}
	policy, err := backup.LoadCustodyPolicy(fixture.profile.CustodyPolicyPath)
	if err != nil {
		t.Fatal(err)
	}
	retentionAdapter, err := localretention.New(localretention.Config{LocalBackup: fixture.profile, ExpectedUID: policy.ControllerUID, Backups: fixture.backups,
		Retirements: fixture.retirements, Inspector: fixture.inspector, Clock: fixture.clock})
	if err != nil {
		t.Fatal(err)
	}
	registry := adapter.NewRegistry()
	if err := registry.Register(localretention.AdapterID, &retirementCompositionRetentionAdapter{t: t, inner: retentionAdapter}); err != nil {
		t.Fatal(err)
	}
	if err := registry.RegisterCredentialResolver(adapter.CredentialCapabilityScope{ResolverID: "native-systemd", ConsumerID: localretention.AdapterID,
		ProfileID: "profile-retirement-composition", CapabilityID: "credential.native.read", Enabled: true}, retirementCompositionResolver{password: fixture.password}); err != nil {
		t.Fatal(err)
	}
	fixture.applyChange(submission.ChangeID, submission.OperationID, key, registry, nil,
		&runengine.CredentialStep{Bindings: credentials, Resolvers: registry, Profiles: retirementCompositionProfiles{revision: 1}})
	successor, err := fixture.backups.GetLocalRetirementSuccessorForPoint(fixture.ctx, survivor.PointID)
	if err != nil || successor.GenerationDigest == "" || successor.SuccessorInventoryDigest == survivor.InventoryDigest || len(successor.Objects) == 0 {
		t.Fatalf("successor=%#v err=%v", successor, err)
	}
}

func (fixture *retirementCompositionFixture) seedActiveRetirementReference(stateRevision int64) {
	fixture.t.Helper()
	db, err := sql.Open("sqlite3", fixture.databasePath)
	if err != nil {
		fixture.t.Fatal(err)
	}
	defer db.Close()
	stamp := fixture.clock().Format(time.RFC3339)
	_, err = db.ExecContext(fixture.ctx, `INSERT INTO credential_reference_versions(version_id,reference_id,consumer_id,purpose_id,target_id,resolver_id,material_version,fingerprint,status,state_revision,recovery_epoch,activated_at,verified_consumers_bytes,declaration_id,declaration_revision,plan_id,plan_digest,run_id,step_id,lease_id,human_id,created_at)
		VALUES('version-retirement-composition','reference-retirement-composition','local.retention','backup-retention',?,'native-systemd','version-retirement-composition',?,'active',1,0,?,?,'credential-fixture',1,'credential-plan',?,'credential-run','credential-step','credential-lease','human-retirement-composition',?)`,
		backupidentity.StandardRepository, compositionDigest("credential-fingerprint"), stamp, []byte(`["local.retention"]`), compositionDigest("credential-plan"), stamp)
	if err != nil {
		fixture.t.Fatalf("seed active credential at revision %d: %v", stateRevision, err)
	}
}

func (fixture *retirementCompositionFixture) applyChange(changeID, operationID, key string, registry *adapter.Registry, retentionCore runengine.CoreEffect, credentialStep *runengine.CredentialStep) generated.Run {
	t := fixture.t
	revisions := store.NewPlanRepository(fixture.authority)
	document, err := store.NewDeclarationRepository(fixture.authority).GetRevision(fixture.ctx, changeID, 1)
	if err != nil {
		t.Fatal(err)
	}
	observations, err := planengine.NewStateObservationReader(revisions)
	if err != nil {
		t.Fatal(err)
	}
	plans, err := planengine.NewService(planengine.Config{Repository: revisions, Observations: observations, Clock: fixture.clock, PolicyVersion: "1.0.0", ToolVersion: "1.0.0",
		ContractVersion: "1.0.0", Risk: "destructive", AuthorizationBranch: "human", ExecutorMode: "central", OperationExecutorID: "executor-central"})
	if err != nil {
		t.Fatal(err)
	}
	current, err := revisions.CurrentRevision(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := observations.CurrentFingerprint(fixture.ctx, document.DeclarationID, document.Operations)
	if err != nil {
		t.Fatal(err)
	}
	created, err := plans.Create(fixture.ctx, planengine.AuthorScope{PrincipalID: fixture.principal.ID, PrincipalMethod: fixture.principal.Method, AgentSessionID: "session-retirement-composition"},
		generated.PlanCreateRequest{Schema: generated.SchemaIDPlanCreateRequest, SchemaVersion: "1.0.0", DeclarationID: document.DeclarationID, DeclarationRevision: document.Revision,
			ExpectedStateRevision: current.StateRevision, RecoveryEpoch: current.RecoveryEpoch, ObservationFingerprint: fingerprint, IdempotencyKey: "plan-" + key, Extensions: document.Extensions})
	if err != nil {
		t.Fatal(err)
	}
	plan := created.Plan
	if len(plan.Operations) != 1 || plan.Operations[0].OperationID != operationID {
		t.Fatalf("planned operation=%#v", plan.Operations)
	}
	reader := retirementCompositionPlanReader{plans: plans}
	approvals, err := acknowledgement.NewService(acknowledgement.Config{Repository: store.NewAcknowledgementRepository(fixture.authority), Plans: reader,
		Authorizer: retirementCompositionAuthorizer{}, Clock: fixture.clock})
	if err != nil {
		t.Fatal(err)
	}
	human := identity.Principal{ID: "human-retirement-composition", Method: identity.SlackSocketModeMethod, Kind: identity.PrincipalHuman}
	card, err := approvals.Request(fixture.ctx, acknowledgement.Scope{Human: human, AuthorityID: "authority-retirement-composition", Nonce: "nonce-" + key}, plan.PlanID)
	if err != nil {
		t.Fatal(err)
	}
	expires, err := time.Parse(time.RFC3339, plan.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := approvals.Decide(fixture.ctx, acknowledgement.Candidate{Human: human, AuthorityID: card.Request.AuthorityID, Action: acknowledgement.ActionApprove,
		PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, TargetDigest: plan.Binding.TargetDigest, ReasonDigest: plan.Binding.ReasonDigest, Nonce: card.Nonce,
		StateRevision: plan.Binding.StateRevision, RecoveryEpoch: plan.Binding.RecoveryEpoch, ExpiresAt: expires, DecidedAt: fixture.clock()})
	if err != nil {
		t.Fatal(err)
	}
	branch := plan.AuthorizationBranch
	decision := generated.AuthorizationDecision{Schema: generated.SchemaIDAuthorizationDecision, SchemaVersion: "1.0.0", DecisionID: "decision-" + key,
		PrincipalID: human.ID, Action: string(authorization.ActionExecute), TargetID: plan.Operations[0].TargetID, Allowed: true, Branch: &branch,
		ReasonCode: authorization.ReasonAllowed, GrantRevision: 1, RecoveryEpoch: plan.Binding.RecoveryEpoch, PlanDigest: plan.PlanDigest,
		DecidedAt: fixture.clock().Format(time.RFC3339), Extensions: []generated.ContractExtension{}}
	if credentialStep != nil {
		credentialStep.Plans = reader
		credentialStep.Clock = fixture.clock
	}
	engine, err := runengine.NewEngine(runengine.Config{Repository: store.NewRunRepository(fixture.authority), Plans: plans,
		Admission: runengine.NewAdmissionGate(approvals, fixture.clock), Adapters: registry, RetentionCore: retentionCore,
		SecretGate: retirementCompositionSecretGate{databasePath: fixture.databasePath}, CredentialStep: credentialStep, Clock: fixture.clock,
		LeaseContext: func(ctx context.Context, _ time.Time) (context.Context, context.CancelFunc) {
			return context.WithCancel(ctx)
		}})
	if err != nil {
		t.Fatal(err)
	}
	request := runengine.SubmitRequest{Reference: generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: plan.PlanID,
		PlanDigest: plan.PlanDigest, RecoveryEpoch: plan.Binding.RecoveryEpoch, IdempotencyKey: "apply-" + key, Extensions: []generated.ContractExtension{}},
		Authorization: decision, Acknowledgement: &proof, Attribution: audit.Attribution{AuthenticatedPrincipalID: human.ID, AuthenticatedPrincipalMethod: human.Method, ResponsibleHumanPrincipalID: &human.ID}}
	if key == "retirement" {
		missing := request
		missing.Reference.IdempotencyKey = "apply-retirement-missing-ack"
		missing.Acknowledgement = nil
		if _, err := engine.Submit(fixture.ctx, missing); err == nil {
			t.Fatal("destructive retirement ran without human acknowledgement")
		}
	}
	result, err := engine.Submit(fixture.ctx, request)
	if err != nil || result.Status != "succeeded" {
		t.Fatalf("apply %s: run=%#v err=%v", key, result, err)
	}
	return result
}

func (fixture *retirementCompositionFixture) verifySuccessorThroughLocalBackup(point store.PendingRecoveryPoint, cycle string) {
	t := fixture.t
	current, err := store.NewPlanRepository(fixture.authority).CurrentRevision(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	plan := fixture.backupPlan
	plan.PlanID = "plan-retirement-successor-verify-" + cycle
	plan.PlanDigest = compositionDigest(plan.PlanID)
	plan.Binding.StateRevision = current.StateRevision
	plan.Binding.RecoveryEpoch = current.RecoveryEpoch
	snapshots, err := store.NewOnlineSnapshotSource(fixture.authority)
	if err != nil {
		t.Fatal(err)
	}
	verificationAdapter, err := New(Config{LocalBackup: fixture.profile, ExpectedUID: uint32(os.Geteuid()), Backups: fixture.backups, Snapshots: snapshots,
		Inspector: fixture.inspector, Trust: NewProtectedLocalDependencyTrust(), LiveProof: true, Plans: fixedPlanSource{plan}, Hooks: backup.DefaultHookRegistry(), Runner: backup.NewResticRunner(), Clock: fixture.clock})
	if err != nil {
		t.Fatal(err)
	}
	operation := adapter.Operation{OperationType: VerifyOperationType, AdapterID: AdapterID, TargetID: point.PointID, InputDigest: point.ManifestDigest, ArtifactDigest: point.InventoryDigest,
		SecretReferences: []adapter.SecretReference{{ID: "retirement-key", Consumer: AdapterID}}}
	password, err := credentialref.NewValue(fixture.password)
	if err != nil {
		t.Fatal(err)
	}
	binding := adapter.ExactExecutionBinding{PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, RunID: "run-retirement-successor-verify-" + cycle, StepID: "step-retirement-successor-verify-" + cycle,
		LeaseID: "lease-retirement-successor-verify-" + cycle, StateRevision: current.StateRevision, RecoveryEpoch: current.RecoveryEpoch, MaximumExpiresAt: fixture.clock().Add(5 * time.Minute).Format(time.RFC3339)}
	effect, verifyErr := verificationAdapter.ExecuteBoundWithCredentials(fixture.ctx, operation, binding, []*credentialref.Value{password})
	password.Close()
	if verifyErr != nil || effect.Status != "succeeded" {
		t.Fatalf("#117 successor reverify: effect=%#v err=%v", effect, verifyErr)
	}
}

func (fixture *retirementCompositionFixture) createAndVerifyPostSuccessorPoint() store.PendingRecoveryPoint {
	t := fixture.t
	current, err := store.NewPlanRepository(fixture.authority).CurrentRevision(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	plan := fixture.backupPlan
	plan.PlanID = "plan-retirement-backup-after-successor"
	plan.PlanDigest = compositionDigest(plan.PlanID)
	plan.Binding.StateRevision = current.StateRevision
	plan.Binding.RecoveryEpoch = current.RecoveryEpoch
	snapshots, err := store.NewOnlineSnapshotSource(fixture.authority)
	if err != nil {
		t.Fatal(err)
	}
	implementation, err := New(Config{LocalBackup: fixture.profile, ExpectedUID: uint32(os.Geteuid()), Backups: fixture.backups, Snapshots: snapshots,
		Inspector: fixture.inspector, Trust: NewProtectedLocalDependencyTrust(), LiveProof: true, Plans: fixedPlanSource{plan}, Hooks: backup.DefaultHookRegistry(), Runner: backup.NewResticRunner(), Clock: fixture.clock})
	if err != nil {
		t.Fatal(err)
	}
	binding := adapter.ExactExecutionBinding{PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, RunID: "run-retirement-backup-after-successor", StepID: "step-retirement-backup-after-successor",
		LeaseID: "lease-retirement-backup-after-successor", StateRevision: current.StateRevision, RecoveryEpoch: current.RecoveryEpoch, MaximumExpiresAt: fixture.clock().Add(5 * time.Minute).Format(time.RFC3339)}
	password, err := credentialref.NewValue(fixture.password)
	if err != nil {
		t.Fatal(err)
	}
	operation := adapter.Operation{OperationType: OperationType, AdapterID: AdapterID, TargetID: "control-retirement-composition", SecretReferences: []adapter.SecretReference{{ID: "retirement-key", Consumer: AdapterID}}}
	effect, runErr := implementation.ExecuteBoundWithCredentials(fixture.ctx, operation, binding, []*credentialref.Value{password})
	password.Close()
	if runErr != nil || effect.PendingPointID == nil {
		t.Fatalf("create post-successor point: effect=%#v err=%v", effect, runErr)
	}
	point, err := fixture.backups.GetPendingRecoveryPoint(fixture.ctx, *effect.PendingPointID)
	if err != nil {
		t.Fatal(err)
	}
	password, err = credentialref.NewValue(fixture.password)
	if err != nil {
		t.Fatal(err)
	}
	binding.RunID, binding.StepID, binding.LeaseID = "run-retirement-verify-after-successor", "step-retirement-verify-after-successor", "lease-retirement-verify-after-successor"
	verify := adapter.Operation{OperationType: VerifyOperationType, AdapterID: AdapterID, TargetID: point.PointID, InputDigest: point.ManifestDigest, ArtifactDigest: point.InventoryDigest,
		SecretReferences: []adapter.SecretReference{{ID: "retirement-key", Consumer: AdapterID}}}
	verified, verifyErr := implementation.ExecuteBoundWithCredentials(fixture.ctx, verify, binding, []*credentialref.Value{password})
	password.Close()
	if verifyErr != nil || verified.Status != "succeeded" {
		t.Fatalf("verify post-successor point: effect=%#v err=%v", verified, verifyErr)
	}
	return point
}

func (fixture *retirementCompositionFixture) assertSecondDraftUsesSuccessorSource() {
	t := fixture.t
	successor, err := fixture.backups.GetLocalRetirementSuccessorForPoint(fixture.ctx, fixture.survivorPoint.PointID)
	if err != nil {
		t.Fatal(err)
	}
	sources, err := fixture.retirements.LoadLocalRetirementDraftSources(fixture.ctx, "standard", 0)
	if err != nil || len(sources.Points) != 2 || len(sources.Objects) == 0 {
		t.Fatalf("second retirement source=%#v successor=%#v err=%v", sources, successor, err)
	}
	foundOld, foundNew := false, false
	newInventory := ""
	for _, point := range sources.Points {
		foundOld = foundOld || point.PointID == fixture.survivorPoint.PointID
		if point.PointID == fixture.nextPoint.PointID {
			foundNew = true
			newInventory = point.InventoryDigest
		}
		if point.PointID == fixture.firstPoint.PointID {
			t.Fatal("retired first-cycle target returned to second-cycle source")
		}
	}
	objects := make([]backup.ExpectedObject, len(sources.Objects))
	for index, object := range sources.Objects {
		objects[index] = backup.ExpectedObject{Type: object.Type, Name: object.Name, Bytes: object.Bytes, Digest: object.Digest}
	}
	if !foundOld || !foundNew || newInventory != fixture.nextPoint.InventoryDigest || backup.ExpectedInventoryDigest(objects) != fixture.nextPoint.InventoryDigest {
		t.Fatalf("second retirement active points=%#v", sources.Points)
	}
}

func compositionDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}
