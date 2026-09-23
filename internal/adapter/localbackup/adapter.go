//go:build linux

// Package localbackup composes the protected local recovery-point creation flow:
// it resolves the exact bound policy, captures the registered source through the
// store-owned online snapshot, runs the pinned restic child (with a sealed
// password FD) against the short-lived custody REST object boundary, binds the
// canonical creation manifest and exact expected inventory, and durably records a
// single PENDING point. It never sets verification evidence or local last-good
// state, never prunes on capacity pressure, and preserves every prior point.
package localbackup

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/backup"
	"github.com/vegastack/vegastack-labs/internal/backupidentity"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// AdapterID and OperationType are the exact provider-neutral identifiers for the
// local backup creation effect.
const (
	AdapterID           = "local.backup"
	OperationType       = "backup.local.create"
	VerifyOperationType = "backup.local.verify"
)

// PlanSource resolves one immutable plan by ID for exact policy-binding readback.
type PlanSource interface {
	GetPlan(context.Context, string) (store.PlanCommitResult, error)
}

// Config wires the protected profile and store-owned collaborators. The profile
// is complete-or-absent: a nil LocalBackup disables the adapter entirely.
type Config struct {
	LocalBackup *serverconfig.LocalBackup
	ExpectedUID uint32
	Backups     *store.BackupRepository
	Snapshots   store.OnlineSnapshotSource
	Inspector   store.RestoredSQLiteInspector
	Trust       DependencyTrustVerifier
	// LiveProof is set only by the protected server runtime. Isolated fixture
	// composition leaves it false, so tests never advance operational last-good.
	LiveProof bool
	Plans     PlanSource
	Hooks     *backup.HookRegistry
	Runner    backup.ResticRunner
	Clock     func() time.Time
}

// Adapter implements the exact bound local backup creation effect.
type Adapter struct {
	config Config
}

// New builds the adapter only when the protected local-backup profile is present
// and complete. A partial or absent profile fails closed.
func New(config Config) (*Adapter, error) {
	if config.LocalBackup == nil || config.Backups == nil || config.Snapshots == nil || config.Plans == nil || config.Hooks == nil || config.Runner == nil {
		return nil, failure.New(generated.ErrorCodePrerequisiteBlocked, "local-backup", false)
	}
	if config.LiveProof && config.Trust == nil {
		return nil, failure.New(generated.ErrorCodePrerequisiteBlocked, "local-backup-trust", false)
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	return &Adapter{config: config}, nil
}

// Execute is the non-credential path. Local backup is always credential-bound, so
// the plain path is never authorized here.
func (adapterImpl *Adapter) Execute(context.Context, adapter.Operation) (adapter.Effect, error) {
	return adapter.Effect{}, backupError(generated.ErrorCodePrerequisiteBlocked, "local-backup-credential-required")
}

// Verify confirms the effect's result digest is present. The manifest digest is
// bound to the point receipt in the same transaction that recorded it.
func (adapterImpl *Adapter) Verify(ctx context.Context, operation adapter.Operation, effect adapter.Effect) (adapter.Verification, error) {
	if effect.Status != "succeeded" || effect.ResultDigest == "" || effect.PendingPointID == nil || *effect.PendingPointID == "" {
		return adapter.Verification{}, backupError(generated.ErrorCodeIntegrityFailure, "local-backup-verify")
	}
	if operation.OperationType == VerifyOperationType {
		proof, err := adapterImpl.config.Backups.GetLocalVerificationByDigest(ctx, effect.ResultDigest)
		if err != nil || proof.PointID != *effect.PendingPointID || proof.PointID != operation.TargetID ||
			proof.ManifestDigest != operation.InputDigest || proof.InventoryDigest != operation.ArtifactDigest ||
			(proof.Status != "local-verified" && proof.Status != "fixture-only") {
			return adapter.Verification{}, backupError(generated.ErrorCodeIntegrityFailure, "local-backup-verify")
		}
		return adapter.Verification{Verified: true, Digest: effect.ResultDigest}, nil
	}
	if operation.OperationType != OperationType {
		return adapter.Verification{}, backupError(generated.ErrorCodeInputInvalid, "local-backup-verify")
	}
	point, err := adapterImpl.config.Backups.GetPendingRecoveryPoint(ctx, *effect.PendingPointID)
	if err != nil || point.ManifestDigest != effect.ResultDigest {
		return adapter.Verification{}, backupError(generated.ErrorCodeIntegrityFailure, "local-backup-verify")
	}
	return adapter.Verification{Verified: true, Digest: effect.ResultDigest}, nil
}

// ExecuteBoundWithCredentials runs one exact policy-bound local backup and records
// a single pending point. Every failure path releases the lease with a failed or
// uncertain job, preserves prior points, and never prunes.
func (adapterImpl *Adapter) ExecuteBoundWithCredentials(ctx context.Context, operation adapter.Operation, binding adapter.ExactExecutionBinding, values []*credentialref.Value) (adapter.Effect, error) {
	if operation.OperationType == VerifyOperationType {
		return adapterImpl.executeBoundVerify(ctx, operation, binding, values)
	}
	if operation.OperationType != OperationType || operation.AdapterID != AdapterID || len(values) != 1 || values[0] == nil {
		return adapter.Effect{}, backupError(generated.ErrorCodePrerequisiteBlocked, "local-backup-binding")
	}
	policy, policyDigest, err := adapterImpl.resolvePolicy(ctx, binding)
	if err != nil {
		return adapter.Effect{}, err
	}
	// The one resolved credential must be exactly the policy's declared encryption
	// key reference, so a different authorized secret cannot initialize the
	// repository while the receipt claims the declared key.
	if policy.EncryptionKeyReferenceID == nil || len(operation.SecretReferences) != 1 ||
		operation.SecretReferences[0].ID != *policy.EncryptionKeyReferenceID {
		return adapter.Effect{}, backupError(generated.ErrorCodePrerequisiteBlocked, "local-backup-key-reference")
	}
	if !backupidentity.Registered(policy.SourceID, policy.SourceSelectors, policy.RepositoryClass, policy.RepositoryID) {
		return adapter.Effect{}, backupError(generated.ErrorCodePrerequisiteBlocked, "local-backup-identity")
	}
	if policy.SourceID != adapterImpl.config.LocalBackup.SourceID ||
		(policy.RepositoryClass == "standard" && *policy.RepositoryID != adapterImpl.config.LocalBackup.StandardRepositoryID) ||
		(policy.RepositoryClass == "critical" && *policy.RepositoryID != adapterImpl.config.LocalBackup.CriticalRepositoryID) {
		return adapter.Effect{}, backupError(generated.ErrorCodePrerequisiteBlocked, "local-backup-profile-identity")
	}
	root, ok := adapterImpl.repositoryRoot(policy.RepositoryClass)
	if !ok {
		return adapter.Effect{}, backupError(generated.ErrorCodePrerequisiteBlocked, "local-backup-repository")
	}
	if err := serverconfig.VerifyLocalBackup(adapterImpl.config.LocalBackup, adapterImpl.config.ExpectedUID); err != nil {
		return adapter.Effect{}, backupError(generated.ErrorCodeIntegrityFailure, "local-backup-profile")
	}
	expectation, err := adapterImpl.config.Snapshots.CurrentExpectation(ctx)
	if err != nil {
		return adapter.Effect{}, backupError(generated.ErrorCodeIntegrityFailure, "local-backup-expectation")
	}
	if expectation.Revision.StateRevision != binding.StateRevision || expectation.Revision.RecoveryEpoch != binding.RecoveryEpoch {
		return adapter.Effect{}, backupError(generated.ErrorCodePlanStale, "local-backup-expectation")
	}

	leaseID, jobID, pointID := "backup-lease-"+randomHex(16), "backup-job-"+randomHex(16), "recovery-point-"+randomHex(16)
	repositoryID := *policy.RepositoryID
	deadline := adapterImpl.leaseDeadline(binding)
	lease := backup.WriterLease{
		PolicyID: policy.PolicyID, PointID: pointID, PlanID: binding.PlanID, PlanDigest: binding.PlanDigest,
		RunID: binding.RunID, StepID: binding.StepID, LeaseID: leaseID, RepositoryID: repositoryID,
		RepositoryClass: policy.RepositoryClass, TargetID: operation.TargetID, SourceRevision: expectation.Revision.StateRevision,
		RecoveryEpoch: binding.RecoveryEpoch, MaximumExpiresAt: deadline,
	}
	if err := adapterImpl.config.Backups.AcquireBackupWriterLease(ctx, store.BackupWriterLeaseRequest{
		LeaseID: leaseID, JobID: jobID, PolicyID: policy.PolicyID, PolicyDigest: policyDigest, PlanID: binding.PlanID,
		PlanDigest: binding.PlanDigest, RunID: binding.RunID, StepID: binding.StepID, RepositoryID: repositoryID,
		RepositoryClass: policy.RepositoryClass, TargetID: operation.TargetID, SourceRevision: expectation.Revision.StateRevision,
		RecoveryEpoch: binding.RecoveryEpoch, MaximumExpiresAt: deadline,
	}); err != nil {
		return adapter.Effect{}, err
	}

	effect, runErr := adapterImpl.runBoundBackup(ctx, policy, policyDigest, repositoryID, root, lease, pointID, binding, expectation, values[0])
	if runErr != nil {
		// Classify a lost/ambiguous publish as uncertain; every other pre-publication
		// failure as failed. Prior points are preserved; nothing is pruned.
		status := "failed"
		if stable, ok := failure.As(runErr); ok && stable.Code == generated.ErrorCodeRecoveryRequired {
			status = "uncertain"
		}
		if cleanupErr := adapterImpl.config.Backups.FailBackupJob(context.WithoutCancel(ctx), leaseID, status); cleanupErr != nil {
			// The job/lease could not be closed; leave the outcome uncertain so
			// recovery reconciles it rather than silently swallowing the error.
			return adapter.Effect{EffectObserved: true}, backupError(generated.ErrorCodeRecoveryRequired, "local-backup-cleanup")
		}
		return effect, runErr
	}
	return effect, nil
}

func (adapterImpl *Adapter) runBoundBackup(ctx context.Context, policy generated.BackupPolicy, policyDigest, repositoryID, root string, lease backup.WriterLease, pointID string, binding adapter.ExactExecutionBinding, expectation store.SnapshotExpectation, password *credentialref.Value) (effect adapter.Effect, outcomeErr error) {
	custodyPolicy, err := backup.LoadCustodyPolicy(adapterImpl.config.LocalBackup.CustodyPolicyPath)
	if err != nil || custodyPolicy.ControllerUID != adapterImpl.config.ExpectedUID || custodyPolicy.StandardRoot != adapterImpl.config.LocalBackup.StandardRoot || custodyPolicy.CriticalRoot != adapterImpl.config.LocalBackup.CriticalRoot {
		return adapter.Effect{}, backupError(generated.ErrorCodeIntegrityFailure, "local-backup-custody-policy")
	}
	maximumBytes := policy.ExpectedBytes + policy.ExpectedGrowthBytes
	if maximumBytes <= 0 {
		return adapter.Effect{}, backupError(generated.ErrorCodePrerequisiteBlocked, "local-backup-custody-bounds")
	}
	session := backup.CustodySession{ProtocolVersion: backup.CustodyProtocolVersion, Role: "writer", PlanID: binding.PlanID, PlanDigest: binding.PlanDigest,
		RunID: binding.RunID, StepID: binding.StepID, LeaseID: lease.LeaseID, RepositoryID: repositoryID, RepositoryClass: policy.RepositoryClass,
		PointID: pointID, SourceID: policy.SourceID, SourceRevision: expectation.Revision.StateRevision, RecoveryEpoch: binding.RecoveryEpoch, MaximumExpiresAt: lease.MaximumExpiresAt,
		MaximumObjects: 1_000_000, MaximumBytes: maximumBytes, WriterLease: &lease}
	launcher := backup.CustodyLauncher{PolicyPath: adapterImpl.config.LocalBackup.CustodyPolicyPath, Writer: &leaseVerifier{backups: adapterImpl.config.Backups},
		Journal: &custodyJournal{backups: adapterImpl.config.Backups}, Clock: adapterImpl.config.Clock}
	custody, err := launcher.Start(ctx, session)
	if err != nil {
		return adapter.Effect{}, backupError(generated.ErrorCodePrerequisiteBlocked, "local-backup-custody")
	}
	defer func() {
		if err := custody.Close(context.WithoutCancel(ctx)); err != nil {
			effect = adapter.Effect{EffectObserved: true}
			outcomeErr = backupError(generated.ErrorCodeRecoveryRequired, "local-backup-custody-close")
		}
	}()
	free, err := custody.Capacity(ctx)
	if err != nil || !capacityAdmitted(free, policy) {
		return adapter.Effect{}, backupError(generated.ErrorCodePrerequisiteBlocked, "local-backup-capacity")
	}

	staging, err := os.MkdirTemp(custodyPolicy.ExchangeRoot, ".vsk-backup-staging-")
	if err != nil {
		return adapter.Effect{}, backupError(generated.ErrorCodeIntegrityFailure, "local-backup-staging")
	}
	defer os.RemoveAll(staging)
	snapshotPath := filepath.Join(staging, "database.sqlite")

	// Bind the exact current consistency expectation so the store-owned snapshot
	// fails closed if the live database drifts during the copy. A zero expectation
	// would never match a migrated production database.
	source := backup.PolicySource{Policy: policy, PolicyDigest: policyDigest, SourceRevision: expectation.Revision.StateRevision, RecoveryEpoch: binding.RecoveryEpoch, Expectation: expectation}
	capture, err := backup.Capture(ctx, source, adapterImpl.config.Snapshots, adapterImpl.config.Hooks, snapshotPath)
	if err != nil {
		return adapter.Effect{}, err
	}
	base := backup.ResticRequest{
		BinaryPath: adapterImpl.config.LocalBackup.ResticBinaryPath, Architecture: runtime.GOARCH,
		RepositoryURL: custody.RepositoryURL(), RepositoryID: repositoryID, RepositoryClass: policy.RepositoryClass,
		RepositoryRoot: root, ExchangeRoot: custodyPolicy.ExchangeRoot, PolicyDigest: policyDigest, Lease: lease,
		ExecutionUID: custodyPolicy.ResticUID, ExecutionGID: custodyPolicy.ResticUID, ControllerUID: custodyPolicy.ControllerUID,
	}
	// Initialize the repository only when it is provably absent (no retained
	// config object). Re-running init against an existing repository-format-v2
	// repository would fail because retained config is immutable, blocking every
	// point after the first.
	before, inventoryErr := custody.Inventory(ctx)
	if inventoryErr != nil {
		return adapter.Effect{}, backupError(generated.ErrorCodeIntegrityFailure, "local-backup-inventory")
	}
	if !inventoryHasConfig(before) {
		initRequest := base
		initRequest.Mode = "init"
		if _, err := custody.RunRestic(ctx, initRequest, password); err != nil {
			return adapter.Effect{}, err
		}
	}
	// The pinned child decrypts the retained config through the guarded REST
	// boundary. A non-v2 repository blocks before any backup write.
	configRequest := base
	configRequest.Mode = "config"
	configRequest.OutputLimit = 64 << 10
	if config, err := custody.RunRestic(ctx, configRequest, password); err != nil || config.RepositoryFormat != 2 {
		return adapter.Effect{}, backupError(generated.ErrorCodeIntegrityFailure, "local-backup-format")
	}
	backupRequest := base
	backupRequest.Mode = "backup"
	backupRequest.SnapshotPath = snapshotPath
	result, err := custody.RunRestic(ctx, backupRequest, password)
	if err != nil {
		return adapter.Effect{}, err
	}
	if result.RepositoryFormat != 2 {
		return adapter.Effect{}, backupError(generated.ErrorCodeIntegrityFailure, "local-backup-format")
	}

	inventory, err := custody.Inventory(ctx)
	if err != nil || len(inventory) == 0 {
		return adapter.Effect{}, backupError(generated.ErrorCodeIntegrityFailure, "local-backup-inventory")
	}

	manifest := backup.CreationManifest{
		Schema: backup.CreationManifestSchema, SchemaVersion: backup.CreationManifestVersion,
		PolicyID: policy.PolicyID, PolicyDigest: policyDigest, PointID: pointID, RunID: binding.RunID, StepID: binding.StepID,
		RepositoryID: repositoryID, RepositoryClass: policy.RepositoryClass, SourceID: policy.SourceID,
		SourceSelectors: append([]string(nil), policy.SourceSelectors...), SourceRevision: capture.Snapshot.Revision.StateRevision,
		RecoveryEpoch: binding.RecoveryEpoch, DatabaseSchemaVersion: capture.Snapshot.SchemaVersion,
		CatalogDigest:     "sha256:" + hex.EncodeToString(capture.Snapshot.CatalogSHA256[:]),
		ContentDigest:     "sha256:" + hex.EncodeToString(capture.Snapshot.DatabaseSHA256[:]),
		ConsistencyHookID: policy.ConsistencyHookID, ConsistencySuccess: capture.Consistency.Success,
		SnapshotID: result.SnapshotID, SnapshotCount: result.SnapshotCount, ExpectedObjectCount: int64(len(inventory)),
		ExpectedObjectBytes: totalBytes(inventory), InventoryDigest: backup.ExpectedInventoryDigest(inventory), ExpectedObjects: inventory,
		DependencyInventoryDigest: backup.ExpectedDependencyInventoryDigest(expectedDependencies(policy)),
		ExpectedDependencies:      expectedDependencies(policy),
		KeyReferenceID:            keyReference(policy), ResticDigest: pinnedResticDigest(), PlatformDigest: platformDigest(),
		SchemaDependencyDigest:    dependencyDigest(policy, "schema"),
		ConfigDependencyDigest:    dependencyDigest(policy, "config"),
		ImageDependencyDigest:     dependencyDigest(policy, "image"),
		SignatureDependencyDigest: dependencyDigest(policy, "signature"),
		StartedAt:                 result.StartedAt.Format(time.RFC3339), CompletedAt: result.CompletedAt.Format(time.RFC3339),
	}
	canonicalManifest, manifestDigest, err := backup.CanonicalCreationManifest(manifest)
	if err != nil {
		return adapter.Effect{}, err
	}
	contentDigest := "sha256:" + hex.EncodeToString(capture.Snapshot.DatabaseSHA256[:])

	rows := make([]store.ExpectedObjectRow, len(inventory))
	for index, object := range inventory {
		rows[index] = store.ExpectedObjectRow{Type: object.Type, Name: object.Name, Bytes: object.Bytes, Digest: object.Digest}
	}
	resultPointID, resultDigest, err := adapterImpl.config.Backups.AppendPendingRecoveryPoint(ctx, store.PendingRecoveryPointRequest{
		LeaseID: lease.LeaseID, PointID: pointID, SnapshotID: result.SnapshotID, SnapshotCount: result.SnapshotCount,
		ObjectCount: int64(len(inventory)), ObjectBytes: totalBytes(inventory), ContentDigest: contentDigest,
		ManifestDigest: manifestDigest, ManifestJSON: canonicalManifest, InventoryDigest: manifest.InventoryDigest, SourceRevision: manifest.SourceRevision,
		RecoveryEpoch: binding.RecoveryEpoch, SourceKind: "local", ProofClass: "fixture", ExpectedObjects: rows,
	})
	if err != nil {
		return adapter.Effect{}, err
	}
	// The central typed receipt identifies the opaque pending point directly;
	// the digest separately binds its canonical manifest. Neither carries a
	// secret, snapshot content, or any verification/last-good claim.
	return adapter.Effect{Status: "succeeded", ResultDigest: resultDigest, PendingPointID: &resultPointID, Changed: true, EffectObserved: true}, nil
}

func (adapterImpl *Adapter) resolvePolicy(ctx context.Context, binding adapter.ExactExecutionBinding) (generated.BackupPolicy, string, error) {
	commit, err := adapterImpl.config.Plans.GetPlan(ctx, binding.PlanID)
	if err != nil {
		return generated.BackupPolicy{}, "", backupError(generated.ErrorCodePlanStale, "local-backup-plan")
	}
	if commit.Plan.PlanDigest != binding.PlanDigest || commit.Plan.Binding.RecoveryEpoch != binding.RecoveryEpoch {
		return generated.BackupPolicy{}, "", backupError(generated.ErrorCodePlanStale, "local-backup-plan")
	}
	digest := ""
	for _, extension := range commit.Plan.Extensions {
		if extension.Name == "x-backup-policy" {
			digest = extension.ValueDigest
		}
	}
	if digest == "" {
		return generated.BackupPolicy{}, "", backupError(generated.ErrorCodeIntegrityFailure, "local-backup-binding")
	}
	draft, err := adapterImpl.config.Backups.GetBackupPolicyDraftByDigest(ctx, digest, binding.RecoveryEpoch)
	if err != nil {
		return generated.BackupPolicy{}, "", backupError(generated.ErrorCodeIntegrityFailure, "local-backup-policy")
	}
	var policy generated.BackupPolicy
	if json.Unmarshal(draft.CanonicalJSON, &policy) != nil || policy.RepositoryClass == "none" {
		return generated.BackupPolicy{}, "", backupError(generated.ErrorCodeIntegrityFailure, "local-backup-policy")
	}
	return policy, digest, nil
}

func (adapterImpl *Adapter) repositoryRoot(class string) (string, bool) {
	switch class {
	case "standard":
		return adapterImpl.config.LocalBackup.StandardRoot, true
	case "critical":
		return adapterImpl.config.LocalBackup.CriticalRoot, true
	default:
		return "", false
	}
}

func (adapterImpl *Adapter) leaseDeadline(binding adapter.ExactExecutionBinding) time.Time {
	if parsed, err := time.Parse(time.RFC3339, binding.MaximumExpiresAt); err == nil {
		return parsed
	}
	return adapterImpl.config.Clock().Add(10 * time.Minute)
}

// leaseVerifier adapts the store's active-lease check to the backup REST
// boundary's LeaseVerifier, keeping the store free of a backup-package import.
type leaseVerifier struct {
	backups *store.BackupRepository
}

func (verifier *leaseVerifier) VerifyWriterLease(lease backup.WriterLease, now time.Time) error {
	return verifier.backups.VerifyActiveWriterLease(context.Background(), lease.LeaseID, lease.RepositoryID, lease.RecoveryEpoch, now)
}

func randomHex(bytes int) string {
	buffer := make([]byte, bytes)
	if _, err := rand.Read(buffer); err != nil {
		return "0000000000000000000000000000000000000000000000000000000000000000"[:bytes*2]
	}
	return hex.EncodeToString(buffer)
}

func totalBytes(objects []backup.ExpectedObject) int64 {
	var total int64
	for _, object := range objects {
		total += object.Bytes
	}
	return total
}

func expectedDependencies(policy generated.BackupPolicy) []backup.ExpectedDependency {
	dependencies := make([]backup.ExpectedDependency, 0, len(policy.Dependencies))
	for _, dependency := range policy.Dependencies {
		dependencies = append(dependencies, backup.ExpectedDependency{
			DependencyID: dependency.DependencyID, Kind: dependency.Kind, Digest: dependency.Digest,
		})
	}
	return dependencies
}

// dependencyDigest returns the declared digest for one dependency kind, or empty
// when the policy declares none of that kind.
func dependencyDigest(policy generated.BackupPolicy, kind string) string {
	for _, dependency := range policy.Dependencies {
		if dependency.Kind == kind {
			return dependency.Digest
		}
	}
	return ""
}

func keyReference(policy generated.BackupPolicy) string {
	if policy.EncryptionKeyReferenceID != nil {
		return *policy.EncryptionKeyReferenceID
	}
	return "none"
}

func pinnedResticDigest() string {
	digest, ok := serverconfig.ExpectedResticExecutableDigest(runtime.GOARCH)
	if !ok {
		return "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	}
	return "sha256:" + digest
}

func platformDigest() string {
	sum := sha256.Sum256([]byte(runtime.GOOS + "/" + runtime.GOARCH))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func capacityAdmitted(free uint64, policy generated.BackupPolicy) bool {
	if policy.ExpectedBytes < 0 || policy.ExpectedGrowthBytes < 0 || policy.MinimumFreeBytes < 0 {
		return false
	}
	required := uint64(policy.ExpectedBytes)
	for _, part := range []int64{policy.ExpectedGrowthBytes, policy.MinimumFreeBytes} {
		if required > ^uint64(0)-uint64(part) {
			return false
		}
		required += uint64(part)
	}
	return free >= required
}

func inventoryHasConfig(objects []backup.ExpectedObject) bool {
	for _, object := range objects {
		if object.Type == "config" && object.Name == "config" {
			return true
		}
	}
	return false
}

// custodyJournal binds process start to the already-durable writer/read lease.
// The enclosing creation/verification transaction owns the terminal outcome;
// response loss is classified uncertain by those existing append-only paths.
type custodyJournal struct {
	backups *store.BackupRepository
	read    *store.BackupReadLeaseRequest
}

func (journal *custodyJournal) BeginCustody(ctx context.Context, session backup.CustodySession) error {
	if journal == nil || journal.backups == nil || (session.Role == "verifier" && journal.read == nil) {
		return backupError(generated.ErrorCodePrerequisiteBlocked, "local-backup-custody-journal")
	}
	return journal.backups.BeginBackupCustody(ctx, store.BackupCustodyAttempt{
		AttemptID: "custody-" + strings.TrimPrefix(session.NonceDigest, "sha256:"), Role: session.Role,
		PlanID: session.PlanID, PlanDigest: session.PlanDigest, RunID: session.RunID, StepID: session.StepID,
		LeaseID: session.LeaseID, RepositoryID: session.RepositoryID, RepositoryClass: session.RepositoryClass, PointID: session.PointID,
		SourceID: session.SourceID, SourceRevision: session.SourceRevision, RecoveryEpoch: session.RecoveryEpoch, MaximumExpiresAt: session.MaximumExpiresAt, NonceDigest: session.NonceDigest,
	})
}
func (journal *custodyJournal) FinishCustody(ctx context.Context, session backup.CustodySession, outcome string) error {
	return journal.backups.FinishBackupCustody(ctx, "custody-"+strings.TrimPrefix(session.NonceDigest, "sha256:"), outcome)
}

func backupError(code, target string) error { return failure.New(code, target, false) }
