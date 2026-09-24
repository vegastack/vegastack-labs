//go:build linux

package server

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/ncruces/go-sqlite3/driver"
	"github.com/vegastack/vegastack-labs/internal/adapter/localbackup"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/backup"
	"github.com/vegastack/vegastack-labs/internal/backupidentity"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/recovery"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/stateexport"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type canaryAcceptanceClock struct {
	base time.Time
	n    atomic.Int64
}

func (clock *canaryAcceptanceClock) Now() time.Time {
	return clock.base.Add(time.Duration(clock.n.Add(1)) * time.Second)
}

type canaryAcceptanceCheckpoint struct {
	authority *store.Store
	clock     func() time.Time
}

func (capability *canaryAcceptanceCheckpoint) ProduceRecoveryCheckpoint(ctx context.Context, request recovery.CanaryRequest, noopRunID string) (store.RecoveryCanaryCheckpointRecord, error) {
	eventID, _, err := capability.authority.RecoveryCanaryNoopEvent(ctx, request.PlanID, noopRunID)
	if err != nil {
		return store.RecoveryCanaryCheckpointRecord{}, err
	}
	chain, err := capability.authority.ChainRange(ctx, audit.EventID(eventID), audit.EventID(eventID))
	if err != nil {
		return store.RecoveryCanaryCheckpointRecord{}, err
	}
	digest := canaryAcceptanceDigest("checkpoint-proof")
	verified := capability.clock().UTC().Format(time.RFC3339)
	payload := []byte("encrypted-independent-checkpoint")
	sum := sha256.Sum256(payload)
	checkpoint := generated.AuditCheckpoint{Schema: generated.SchemaIDAuditCheckpoint, SchemaVersion: "1.1.0", CheckpointID: "checkpoint-canary-composition", FirstEventID: eventID, LastEventID: eventID, ChainDigest: string(chain.RangeDigest), InstanceID: request.NewInstanceID, FirstSegmentSequence: chain.Links[0].SegmentSequence, LastSegmentSequence: chain.Links[0].SegmentSequence, SignerReferenceID: "independent-signer", SignerMaterialVersion: "version-a", SignatureDigest: &digest, PublicKeyID: ptrString("independent-key"), ExportReceiptDigest: &digest, IndependentReadDigest: &digest, IndependentCopyDigest: &digest, Status: "anchored", ReasonCode: "independent-match", SourceKind: "independent", ProofClass: "live", VerifiedAt: &verified, VerificationStatus: "verified", RecoveryEpoch: request.RecoveryEpoch}
	return store.RecoveryCanaryCheckpointRecord{Checkpoint: checkpoint, ExactPath: "audit-anchor/checkpoint-canary-composition.json.enc", EncryptedPayload: payload, PayloadDigest: "sha256:" + hex.EncodeToString(sum[:]), CapabilityObservedAt: capability.clock().UTC()}, nil
}

type canaryAcceptanceBorrower struct{}

func (canaryAcceptanceBorrower) BorrowRecoveryCanaryCredential(context.Context, localbackup.RecoveryCredentialRequest, int64) (*credentialref.Value, error) {
	return credentialref.NewValue([]byte("hermetic-recovery-password"))
}

type canaryAcceptanceCustodyState struct {
	mu           sync.Mutex
	clock        func() time.Time
	snapshot     []byte
	snapshotPath string
	snapshotID   string
	inventory    []backup.ExpectedObject
	resticModes  []string
}

func (state *canaryAcceptanceCustodyState) Start(ctx context.Context, session backup.CustodySession, writer backup.LeaseVerifier, reader backup.ReadLeaseVerifier, journal backup.CustodyJournal) (backup.CustodyClient, error) {
	if writer != nil && writer.VerifyWriterLease(*session.WriterLease, state.clock()) != nil {
		return nil, os.ErrPermission
	}
	if reader != nil && reader.VerifyReadLease(*session.ReadLease, state.clock()) != nil {
		return nil, os.ErrPermission
	}
	if err := journal.BeginCustody(ctx, session); err != nil {
		return nil, err
	}
	return &canaryAcceptanceCustodyClient{state: state, session: session, journal: journal}, nil
}

type canaryAcceptanceCustodyClient struct {
	state   *canaryAcceptanceCustodyState
	session backup.CustodySession
	journal backup.CustodyJournal
}

func (*canaryAcceptanceCustodyClient) RepositoryURL() string { return "http+unix://hermetic:/repo/" }
func (client *canaryAcceptanceCustodyClient) Inventory(context.Context) ([]backup.ExpectedObject, error) {
	client.state.mu.Lock()
	defer client.state.mu.Unlock()
	return append([]backup.ExpectedObject(nil), client.state.inventory...), nil
}
func (client *canaryAcceptanceCustodyClient) InventoryExpected(_ context.Context, expected []backup.ExpectedObject) ([]backup.ExpectedObject, error) {
	return append([]backup.ExpectedObject(nil), expected...), nil
}
func (*canaryAcceptanceCustodyClient) Capacity(context.Context) (uint64, error) { return 1 << 30, nil }
func (*canaryAcceptanceCustodyClient) CapacitySnapshot(context.Context) (backup.RepositoryCapacity, error) {
	return backup.RepositoryCapacity{TotalBytes: 1 << 30, AvailableBytes: 1 << 29}, nil
}
func (client *canaryAcceptanceCustodyClient) RunRestic(_ context.Context, request backup.ResticRequest, _ *credentialref.Value) (backup.ResticResult, error) {
	client.state.mu.Lock()
	defer client.state.mu.Unlock()
	started, completed := client.state.clock().UTC(), client.state.clock().UTC()
	result := backup.ResticResult{RepositoryFormat: 2, StartedAt: started, CompletedAt: completed}
	client.state.resticModes = append(client.state.resticModes, request.Mode)
	switch request.Mode {
	case "init", "config", "check-full":
		return result, nil
	case "backup":
		body, err := os.ReadFile(request.SnapshotPath)
		if err != nil {
			return backup.ResticResult{}, err
		}
		client.state.snapshot = body
		client.state.snapshotPath = request.SnapshotPath
		client.state.snapshotID = strings.Repeat("8", 64)
		client.state.inventory = []backup.ExpectedObject{{Type: "config", Name: "config", Bytes: 64, Digest: canaryAcceptanceDigest("config")}, {Type: "data", Name: strings.Repeat("9", 64), Bytes: int64(len(body)), Digest: canaryAcceptanceDigest("data")}, {Type: "keys", Name: strings.Repeat("a", 64), Bytes: 64, Digest: canaryAcceptanceDigest("keys")}, {Type: "snapshots", Name: client.state.snapshotID, Bytes: 128, Digest: canaryAcceptanceDigest("snapshot")}}
		result.SnapshotID, result.SnapshotCount = client.state.snapshotID, 1
		return result, nil
	case "snapshots":
		result.SnapshotPaths = map[string][]string{client.state.snapshotID: {client.state.snapshotPath}}
		return result, nil
	case "restore":
		relative := strings.TrimPrefix(client.state.snapshotPath, string(filepath.Separator))
		target := filepath.Join(request.RestoreTarget, relative)
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return backup.ResticResult{}, err
		}
		if err := os.WriteFile(target, client.state.snapshot, 0o600); err != nil {
			return backup.ResticResult{}, err
		}
		return result, nil
	default:
		return backup.ResticResult{}, os.ErrInvalid
	}
}
func (*canaryAcceptanceCustodyClient) RunOffsiteRestic(context.Context, backup.OffsiteResticRequest, *credentialref.Value, []byte) (backup.OffsiteResticResult, error) {
	return backup.OffsiteResticResult{}, os.ErrInvalid
}
func (*canaryAcceptanceCustodyClient) ResticObservation() backup.ResticObservation {
	return backup.ResticObservation{}
}
func (client *canaryAcceptanceCustodyClient) Close(ctx context.Context) error {
	return client.journal.FinishCustody(ctx, client.session, "succeeded")
}

type canaryAcceptanceTrust struct{}

func (canaryAcceptanceTrust) VerifyCurrent(_ context.Context, request localbackup.DependencyTrustRequest) ([]localbackup.DependencyTrustEvidence, error) {
	evidence := make([]localbackup.DependencyTrustEvidence, len(request.Expected))
	for i, dependency := range request.Expected {
		evidence[i] = localbackup.DependencyTrustEvidence{DependencyID: dependency.DependencyID, Kind: dependency.Kind, Digest: dependency.Digest, SourceKind: "protected-local-pin", PointID: request.PointID, PolicyDigest: request.PolicyDigest, SourceID: "protected-local-pin", StateRevision: request.StateRevision, RecoveryEpoch: request.RecoveryEpoch}
	}
	return evidence, nil
}

type canaryAcceptanceFormerWriter struct{}

func (canaryAcceptanceFormerWriter) VerifyFormerWriterDenied(context.Context, recovery.CanaryRequest) error {
	return nil
}

func TestOperationsRunRecoveryCanaryCreatesDurableCheckpointAndCurrentBackup(t *testing.T) {
	ctx := context.Background()
	clock := &canaryAcceptanceClock{base: time.Date(2026, 9, 24, 6, 0, 0, 0, time.UTC)}
	directory := shortServerTempDir(t)
	databasePath := filepath.Join(directory, "control.db")
	config := store.Config{DatabasePath: databasePath, Mode: store.InitializeNew, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "test", BuildVersion: "test", Clock: clock.Now}
	authority, err := store.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	prior, err := authority.CurrentAuthority(ctx)
	if err != nil {
		t.Fatal(err)
	}
	backups := store.NewBackupRepository(authority)
	policy, priorPoint := seedCanaryAcceptanceSource(t, backups, clock.Now)
	plan, readable, binding, request := canaryAcceptanceBundle(t, prior, priorPoint)
	if err := authority.PrepareRecoveredAuthority(ctx, binding, audit.Fingerprint(canaryAcceptanceDigest("prior-checkpoint"))); err != nil {
		t.Fatal(err)
	}
	if _, err := authority.WriteRecoveredAuthorityBundle(ctx, store.RecoveredAuthorityBundle{Plan: plan, Readable: readable, Request: request, Binding: binding, Status: "verification-required"}); err != nil {
		t.Fatal(err)
	}
	health, err := authority.Health(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.GetAuditCheckpoint(ctx, "checkpoint-canary-composition"); store.Code(err) != generated.ErrorCodeResourceNotFound {
		t.Fatalf("canary checkpoint existed before execution: %v", err)
	}
	if points, _ := backups.CurrentLocalLastGood(ctx, policy.RepositoryClass); points != "" {
		t.Fatal("current-epoch last-good existed before canary")
	}
	if _, err := backups.CurrentLocalRecoverySource(ctx, policy.RepositoryClass); store.Code(err) != generated.ErrorCodePrerequisiteBlocked {
		t.Fatalf("current-epoch recovery source existed before canary: %v", err)
	}
	if err := authority.Close(); err != nil {
		t.Fatal(err)
	}

	profileJSON := generated.ServerProfile{Schema: generated.SchemaIDServerProfile, SchemaVersion: "1.3.0", SocketPath: filepath.Join(directory, "control.sock"), SocketOwnerUID: int64(os.Geteuid()), SocketMode: "0600", ShutdownGraceSeconds: 5, InventoryExportRoot: filepath.Join(directory, "exports"), PrincipalBindings: []generated.LocalPrincipalBinding{{UID: int64(os.Geteuid()), PrincipalID: "principal.canary"}}}
	if err := os.Mkdir(profileJSON.InventoryExportRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	standard, critical, exchange := filepath.Join(directory, "standard"), filepath.Join(directory, "critical"), filepath.Join(directory, "exchange")
	for _, path := range []string{standard, critical, exchange} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	resticPath, custodyPath := filepath.Join(directory, "restic"), filepath.Join(directory, "custody.json")
	profileJSON.StandardBackupRoot, profileJSON.CriticalBackupRoot = &standard, &critical
	profileJSON.ResticBinaryPath, profileJSON.CustodyPolicyPath = &resticPath, &custodyPath
	configPath := filepath.Join(directory, "server-profile.json")
	writeProtectedJSON(t, configPath, profileJSON)
	build := result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}
	operations := NewOperations(build, func() (string, error) { return "request-canary-composition", nil })
	operations.databasePath = databasePath
	operations.platformProbe = fixedPlatformProbe{platform: testSupportedPlatform()}
	operations.openStore = func(ctx context.Context, input store.Config) (*store.Store, error) {
		input.Clock = clock.Now
		return store.Open(ctx, input)
	}
	custody := &canaryAcceptanceCustodyState{clock: clock.Now}
	operations.localBackupAdapter = func(config localbackup.Config) (*localbackup.Adapter, error) {
		config.Clock = clock.Now
		config.CustodyStart = custody.Start
		config.CustodyPolicy = func(string) (backup.CustodyPolicy, error) {
			return backup.CustodyPolicy{SchemaVersion: "1.0.0", StandardRoot: standard, CriticalRoot: critical, ControllerUID: uint32(os.Geteuid()), ExchangeRoot: exchange}, nil
		}
		config.ProfileVerifier = func(*serverconfig.LocalBackup, uint32) error { return nil }
		config.Trust = canaryAcceptanceTrust{}
		return localbackup.New(config)
	}
	operations.localRecoverySource = func(*serverconfig.LocalBackup, uint32, *store.BackupRepository, store.RestoredSQLiteInspector, localbackup.RecoveryCredentialSource, localbackup.DependencyTrustVerifier, store.OnlineSnapshotSource) (recovery.SnapshotResolver, recovery.CompatibilityVerifier, recovery.AuditPositionVerifier, error) {
		return nil, nil, nil, nil
	}
	operations.recoveryCanaryBorrower = func(recoveryCredentialBorrower) recoveryCanaryCredentialBorrower { return canaryAcceptanceBorrower{} }
	checkpoint := &canaryAcceptanceCheckpoint{clock: clock.Now}
	operations.recoveryCanaryPorts = func(_ context.Context, _ serverconfig.Profile, authority *store.Store, _ *store.BackupRepository) (recovery.CanaryAuditVerifier, recovery.CanaryBackupVerifier, error) {
		checkpoint.authority = authority
		return recovery.IndependentCheckpointCanary{Appender: &durableRecoveryCheckpointAppender{authority: authority, capability: checkpoint}, Reader: authority}, nil, nil
	}
	operations.recoveryFormerWriter = func(*store.RestoreRepository, recovery.ExactFenceRefresher) recovery.FormerWriterVerifier {
		return canaryAcceptanceFormerWriter{}
	}
	composed := make(chan recovery.CanaryVerifier, 1)
	operations.recoveryCanaryObserve = func(verifier recovery.CanaryVerifier) { composed <- verifier }
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- operations.Run(runCtx, configPath) }()
	var verifier recovery.CanaryVerifier
	select {
	case verifier = <-composed:
	case err := <-done:
		t.Fatalf("Operations.Run stopped before canary composition: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Operations.Run did not compose recovery canary")
	}
	verifier.Clock = clock.Now
	result, err := verifier.Verify(ctx, recovery.CanaryRequest{PlanID: binding.PlanID, PlanDigest: binding.PlanDigest, NewInstanceID: binding.NewInstanceID, FenceSetDigest: binding.FenceSetDigest, CanaryRunID: binding.CanaryRunID, CanaryStepID: binding.CanaryStepID, CanaryLeaseID: binding.CanaryLeaseID, CanaryChallengeID: binding.CanaryChallengeID, CanaryReceiptID: binding.CanaryReceiptID, RecoveryEpoch: binding.NextRecoveryEpoch, ExpectedStateRevision: health.Revision.StateRevision, ResponsibleHumanID: "principal.canary", PrincipalMethod: "local-os-peer"})
	if err != nil {
		t.Fatalf("composed canary: %v", err)
	}
	custody.mu.Lock()
	modes := append([]string(nil), custody.resticModes...)
	snapshotBytes := len(custody.snapshot)
	custody.mu.Unlock()
	for _, required := range []string{"backup", "snapshots", "check-full", "restore"} {
		if !slices.Contains(modes, required) {
			t.Fatalf("real local backup path did not call custody mode %q: %v", required, modes)
		}
	}
	if snapshotBytes == 0 {
		t.Fatal("real local backup path did not capture a database snapshot")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	assertCanaryAcceptanceDurability(t, databasePath, binding, result)
}

func canaryAcceptanceDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}
func ptrString(value string) *string { return &value }

func seedCanaryAcceptanceSource(t *testing.T, repository *store.BackupRepository, now func() time.Time) (generated.BackupPolicy, store.PendingRecoveryPoint) {
	t.Helper()
	resticSHA256, ok := serverconfig.ExpectedResticExecutableDigest(runtime.GOARCH)
	if !ok {
		t.Fatal("missing pinned restic digest")
	}
	resticDigest := "sha256:" + resticSHA256
	repositoryID, encryptionID, recoveryID := backupidentity.StandardRepository, "key-canary", "key-recovery"
	policy := generated.BackupPolicy{Schema: generated.SchemaIDBackupPolicy, SchemaVersion: "1.2.0", PolicyID: "policy-canary", OwnerID: "owner-canary", SourceID: backupidentity.ControlDatabaseSource, SourceSelectors: []string{backupidentity.ControlDatabaseSelector}, ConsistencyHookID: backup.SQLiteOnlineHookID, RepositoryID: &repositoryID, RepositoryClass: "standard", ScheduleIntent: "manual", ExpectedBytes: 1 << 20, ExpectedGrowthBytes: 1 << 20, MinimumFreeBytes: 1, EncryptionKeyReferenceID: &encryptionID, RecoveryKeyReferenceID: &recoveryID, RetentionDays: 7, RestoreTargetID: "control-canary", Dependencies: []generated.BackupDependency{{DependencyID: "restic", Kind: "binary", Digest: resticDigest}}, FunctionalTestRequired: true, FullPayloadIntervalHours: 24, FunctionalTestIntervalHours: 24, RecoveryEpoch: 0, Revision: 1}
	_, sum, err := stateexport.CanonicalJSON(policy)
	if err != nil {
		t.Fatal(err)
	}
	submission, err := repository.CreateBackupPolicyDraft(context.Background(), generated.BackupPolicyDraftRequest{Schema: generated.SchemaIDBackupPolicyDraftRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: 0, RecoveryEpoch: 0, TargetDigest: "sha256:" + hex.EncodeToString(sum[:]), IdempotencyKey: "seed-canary-policy", Policy: policy}, audit.Attribution{AuthenticatedPrincipalID: "principal.canary", AuthenticatedPrincipalMethod: "local-os-peer"})
	if err != nil {
		t.Fatal(err)
	}
	leaseID, pointID, snapshotID := "writer-prior", "point-prior", strings.Repeat("7", 64)
	if err := repository.AcquireBackupWriterLease(context.Background(), store.BackupWriterLeaseRequest{LeaseID: leaseID, JobID: "job-prior", PolicyID: policy.PolicyID, PolicyDigest: submission.PolicyDigest, PlanID: "plan-prior", PlanDigest: canaryAcceptanceDigest("plan-prior"), RunID: "run-prior", StepID: "step-prior", RepositoryID: repositoryID, RepositoryClass: "standard", TargetID: policy.RestoreTargetID, SourceRevision: 0, RecoveryEpoch: 0, MaximumExpiresAt: now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	objects := []store.ExpectedObjectRow{{Type: "config", Name: "config", Bytes: 64, Digest: canaryAcceptanceDigest("prior-config")}, {Type: "data", Name: strings.Repeat("6", 64), Bytes: 128, Digest: canaryAcceptanceDigest("prior-data")}, {Type: "keys", Name: strings.Repeat("5", 64), Bytes: 64, Digest: canaryAcceptanceDigest("prior-keys")}, {Type: "snapshots", Name: snapshotID, Bytes: 128, Digest: canaryAcceptanceDigest("prior-snapshot")}}
	expected := make([]backup.ExpectedObject, len(objects))
	for i, object := range objects {
		expected[i] = backup.ExpectedObject{Type: object.Type, Name: object.Name, Bytes: object.Bytes, Digest: object.Digest}
	}
	dependencies := []backup.ExpectedDependency{{DependencyID: "restic", Kind: "binary", Digest: resticDigest}}
	stamp := now().UTC()
	manifest := backup.CreationManifest{Schema: backup.CreationManifestSchema, SchemaVersion: backup.CreationManifestVersion, PolicyID: policy.PolicyID, PolicyDigest: submission.PolicyDigest, PointID: pointID, RunID: "run-prior", StepID: "step-prior", RepositoryID: repositoryID, RepositoryClass: "standard", SourceID: policy.SourceID, SourceSelectors: policy.SourceSelectors, SourceRevision: 0, RecoveryEpoch: 0, DatabaseSchemaVersion: 24, CatalogDigest: canaryAcceptanceDigest("prior-catalog"), ContentDigest: canaryAcceptanceDigest("prior-content"), ConsistencyHookID: policy.ConsistencyHookID, ConsistencySuccess: true, SnapshotID: snapshotID, SnapshotCount: 1, ExpectedObjectCount: int64(len(objects)), ExpectedObjectBytes: 384, InventoryDigest: backup.ExpectedInventoryDigest(expected), ExpectedObjects: expected, DependencyInventoryDigest: backup.ExpectedDependencyInventoryDigest(dependencies), ExpectedDependencies: dependencies, KeyReferenceID: encryptionID, ResticDigest: resticDigest, PlatformDigest: canaryAcceptanceDigest("platform"), StartedAt: stamp.Add(-time.Second).Format(time.RFC3339), CompletedAt: stamp.Format(time.RFC3339)}
	body, digest, err := backup.CanonicalCreationManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := repository.AppendPendingRecoveryPoint(context.Background(), store.PendingRecoveryPointRequest{LeaseID: leaseID, PointID: pointID, SnapshotID: snapshotID, SnapshotCount: 1, ObjectCount: int64(len(objects)), ObjectBytes: 384, ContentDigest: manifest.ContentDigest, ManifestDigest: digest, ManifestJSON: body, InventoryDigest: manifest.InventoryDigest, SourceRevision: 0, RecoveryEpoch: 0, SourceKind: "local", ProofClass: "fixture", ExpectedObjects: objects}); err != nil {
		t.Fatal(err)
	}
	point, err := repository.GetPendingRecoveryPoint(context.Background(), pointID)
	if err != nil {
		t.Fatal(err)
	}
	return policy, point
}

func canaryAcceptanceBundle(t *testing.T, prior store.AuthorityState, point store.PendingRecoveryPoint) (generated.Plan, string, generated.RestoreBinding, generated.RestoreRequest) {
	t.Helper()
	digest := canaryAcceptanceDigest("binding")
	binding := processRecoveryBinding(prior.InstanceID, prior.RecoveryEpoch)
	binding.Source.PointID, binding.PointID = point.PointID, point.PointID
	binding.Source.PointDigest, binding.Source.ManifestDigest = point.ManifestDigest, point.ManifestDigest
	binding.Source.RecoveryEpoch = prior.RecoveryEpoch
	binding.Source.KeyReferenceID = "key-canary"
	binding.TargetDigest, binding.FenceSetDigest, binding.AuditDecisionDigest, binding.CandidateDigest = canaryAcceptanceDigest("target"), canaryAcceptanceDigest("fence"), canaryAcceptanceDigest("decision"), canaryAcceptanceDigest("candidate")
	request := canaryAcceptanceRestoreRequest(binding)
	canaryDigest, err := change.RestoreCanaryBindingDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	binding.CanaryBindingDigest, request.CanaryBindingDigest = canaryDigest, canaryDigest
	readable := "recovery canary composition plan\n"
	readableSum := sha256.Sum256([]byte(readable))
	created := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	plan := generated.Plan{Schema: generated.SchemaIDPlan, SchemaVersion: "1.0.0", DeclarationID: "declaration-canary-composition", Binding: generated.PlanBinding{RecoveryEpoch: prior.RecoveryEpoch, PriorStateRevision: 0, StateRevision: 1, DeclarationRevision: 1, ObservationFingerprint: digest, TargetDigest: binding.TargetDigest, ReasonDigest: digest, PolicyVersion: "1.0.0", ToolVersion: "test", ContractVersion: "1.0.0"}, Operations: []generated.PlanOperation{{Sequence: 1, OperationID: binding.RecoveryStepID, OperationType: "recovery.restore.cutover", AdapterID: "core.recovery", ExecutorID: "executor-central", TargetID: binding.TargetIDs[0], InputDigest: digest, ArtifactDigest: digest, Idempotent: false}, {Sequence: 2, OperationID: binding.CanaryStepID, OperationType: "recovery.canary.noop", AdapterID: "core.recovery", ExecutorID: "executor-central", TargetID: binding.NewInstanceID, InputDigest: canaryDigest, ArtifactDigest: canaryDigest, Idempotent: true}}, Status: "planned", Risk: "control-plane", AuthorizationBranch: "human", ExecutorMode: "central", CreatedAt: created.Format(time.RFC3339), ExpiresAt: created.Add(time.Hour).Format(time.RFC3339), ReadableDigest: "sha256:" + hex.EncodeToString(readableSum[:]), Extensions: []generated.ContractExtension{}}
	preimage, _ := json.Marshal(plan)
	planSum := sha256.Sum256(preimage)
	plan.PlanDigest = "sha256:" + hex.EncodeToString(planSum[:])
	plan.PlanID = "plan-" + hex.EncodeToString(planSum[:16])
	binding.PlanID, binding.PlanDigest = plan.PlanID, plan.PlanDigest
	request = canaryAcceptanceRestoreRequest(binding)
	return plan, readable, binding, request
}

func canaryAcceptanceRestoreRequest(binding generated.RestoreBinding) generated.RestoreRequest {
	fence := generated.RestoreFenceItem{Schema: generated.SchemaIDRestoreFenceItem, SchemaVersion: "1.1.0", Boundary: "host-service", SubjectID: "former-control", TargetID: binding.TargetIDs[0], AdapterID: "adapter-a", FormerIdentityID: "former-identity", RequiredEvidenceKinds: []string{"service-denied"}, Required: true, EvidenceIDs: []string{binding.SourceAdmissionDigest, binding.FenceQualificationDigest}, EvidenceDigest: binding.FenceSetDigest, Status: "required"}
	decision := generated.RestoreAuditDecision{Schema: generated.SchemaIDRestoreAuditDecision, SchemaVersion: "1.1.0", IndependentCheckpointDigest: binding.AuditDecisionDigest, Strategy: "matched", DecisionDigest: binding.AuditDecisionDigest}
	return generated.RestoreRequest{Schema: generated.SchemaIDRestoreRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: binding.PriorRecoveryEpoch, RecoveryEpoch: binding.PriorRecoveryEpoch, TargetDigest: binding.TargetDigest, IdempotencyKey: "restore-plan-canary", Source: binding.Source, Fences: []generated.RestoreFenceItem{fence}, AuditDecision: decision, PointID: binding.PointID, DependencyIDs: binding.DependencyIDs, TargetIDs: binding.TargetIDs, PriorInstanceID: binding.PriorInstanceID, NewInstanceID: binding.NewInstanceID, PriorRecoveryEpoch: binding.PriorRecoveryEpoch, NextRecoveryEpoch: binding.NextRecoveryEpoch, FenceSetDigest: binding.FenceSetDigest, AuditDecisionDigest: binding.AuditDecisionDigest, CandidateDigest: binding.CandidateDigest, FormerHostID: binding.FormerHostID, ReplacementHostID: binding.ReplacementHostID, RecoveryDraftID: binding.RecoveryDraftID, CiphertextFingerprint: binding.CiphertextFingerprint, SourceAdmissionDigest: binding.SourceAdmissionDigest, FenceQualificationDigest: binding.FenceQualificationDigest, RecoveryRunID: binding.RecoveryRunID, RecoveryStepID: binding.RecoveryStepID, RecoveryLeaseID: binding.RecoveryLeaseID, RecoveryChallengeID: binding.RecoveryChallengeID, RecoveryReceiptID: binding.RecoveryReceiptID, CanaryRunID: binding.CanaryRunID, CanaryStepID: binding.CanaryStepID, CanaryLeaseID: binding.CanaryLeaseID, CanaryChallengeID: binding.CanaryChallengeID, CanaryReceiptID: binding.CanaryReceiptID, CanaryBindingDigest: binding.CanaryBindingDigest}
}

func assertCanaryAcceptanceDurability(t *testing.T, path string, binding generated.RestoreBinding, result generated.RestoreCanaryResult) {
	t.Helper()
	database, err := sql.Open("sqlite3", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var noopAt, pointAt, verificationAt, advancedAt, manifestJSON, runID, stepID, leaseID string
	if err := database.QueryRow(`SELECT created_at,run_id,step_id,lease_id FROM recovery_canary_runs WHERE plan_id=?`, binding.PlanID).Scan(&noopAt, &runID, &stepID, &leaseID); err != nil {
		t.Fatal(err)
	}
	if runID != binding.CanaryRunID || stepID != binding.CanaryStepID || leaseID != binding.CanaryLeaseID || result.NoopRunID != binding.CanaryRunID {
		t.Fatalf("durable noop binding = %s/%s/%s", runID, stepID, leaseID)
	}
	var checkpointJSON []byte
	if err := database.QueryRow(`SELECT canonical_bytes FROM audit_checkpoints WHERE checkpoint_id=?`, result.AuditCheckpointID).Scan(&checkpointJSON); err != nil {
		t.Fatal(err)
	}
	var checkpoint generated.AuditCheckpoint
	if json.Unmarshal(checkpointJSON, &checkpoint) != nil || checkpoint.InstanceID != binding.NewInstanceID || checkpoint.RecoveryEpoch != binding.NextRecoveryEpoch || checkpoint.VerifiedAt == nil {
		t.Fatalf("durable checkpoint = %#v", checkpoint)
	}
	if err := database.QueryRow(`SELECT manifest_json,created_at FROM recovery_points WHERE point_id=?`, result.BackupPointID).Scan(&manifestJSON, &pointAt); err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		RunID  string `json:"runId"`
		StepID string `json:"stepId"`
	}
	if json.Unmarshal([]byte(manifestJSON), &manifest) != nil || manifest.RunID != binding.CanaryRunID || manifest.StepID != binding.CanaryStepID {
		t.Fatalf("durable point binding = %#v", manifest)
	}
	if err := database.QueryRow(`SELECT created_at FROM backup_local_verifications WHERE point_id=? AND status='local-verified' AND proof_class='live'`, result.BackupPointID).Scan(&verificationAt); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT advanced_at FROM backup_local_last_good WHERE point_id=? AND recovery_epoch=?`, result.BackupPointID, binding.NextRecoveryEpoch).Scan(&advancedAt); err != nil {
		t.Fatal(err)
	}
	parse := func(value string) time.Time {
		at, err := time.Parse(time.RFC3339, value)
		if err != nil {
			t.Fatal(err)
		}
		return at
	}
	checkpointAt := parse(*checkpoint.VerifiedAt)
	if checkpointAt.Before(parse(noopAt)) || parse(pointAt).Before(parse(noopAt)) || parse(verificationAt).Before(parse(pointAt)) || parse(advancedAt).Before(parse(verificationAt)) {
		t.Fatalf("causal timestamps noop=%s checkpoint=%s point=%s verification=%s last-good=%s", noopAt, *checkpoint.VerifiedAt, pointAt, verificationAt, advancedAt)
	}
}
