//go:build linux

// Package localbackup composes the protected local recovery-point creation flow:
// it resolves the exact bound policy, captures the registered source through the
// store-owned online snapshot, runs the pinned restic child (with a sealed
// password FD) against the same-process guarded REST object boundary, binds the
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
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/unix"

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
	AdapterID     = "local.backup"
	OperationType = "backup.local.create"
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
	Plans       PlanSource
	Hooks       *backup.HookRegistry
	Runner      backup.ResticRunner
	Clock       func() time.Time
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
func (adapterImpl *Adapter) Verify(ctx context.Context, _ adapter.Operation, effect adapter.Effect) (adapter.Verification, error) {
	if effect.Status != "succeeded" || effect.ResultDigest == "" || effect.PendingPointID == nil || *effect.PendingPointID == "" {
		return adapter.Verification{}, backupError(generated.ErrorCodeIntegrityFailure, "local-backup-verify")
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

func (adapterImpl *Adapter) runBoundBackup(ctx context.Context, policy generated.BackupPolicy, policyDigest, repositoryID, root string, lease backup.WriterLease, pointID string, binding adapter.ExactExecutionBinding, expectation store.SnapshotExpectation, password *credentialref.Value) (adapter.Effect, error) {
	// Capacity admission: a full destination blocks a new backup without prune.
	if err := admitCapacity(root, policy); err != nil {
		return adapter.Effect{}, err
	}

	staging, err := os.MkdirTemp(filepath.Dir(root), ".vsk-backup-staging-")
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

	socketDir, err := os.MkdirTemp(filepath.Dir(root), ".vsk-backup-socket-")
	if err != nil {
		return adapter.Effect{}, backupError(generated.ErrorCodeIntegrityFailure, "local-backup-socket")
	}
	defer os.RemoveAll(socketDir)
	socketPath := filepath.Join(socketDir, "rest.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return adapter.Effect{}, backupError(generated.ErrorCodeIntegrityFailure, "local-backup-socket")
	}
	defer listener.Close()

	verifier := &leaseVerifier{backups: adapterImpl.config.Backups}
	restServer, err := backup.NewRESTServer(root, adapterImpl.config.ExpectedUID, lease, verifier, adapterImpl.config.Clock)
	if err != nil {
		return adapter.Effect{}, backupError(generated.ErrorCodeIntegrityFailure, "local-backup-rest")
	}
	serveCtx, cancelServe := context.WithCancel(ctx)
	defer cancelServe()
	go func() { _ = restServer.Serve(serveCtx, listener) }()

	repositoryURL := "http+unix://" + socketPath + ":/" + repositoryID + "/"
	base := backup.ResticRequest{
		BinaryPath: adapterImpl.config.LocalBackup.ResticBinaryPath, Architecture: runtime.GOARCH,
		RepositoryURL: repositoryURL, RepositoryID: repositoryID, RepositoryClass: policy.RepositoryClass,
		RepositoryRoot: root, PolicyDigest: policyDigest, Lease: lease,
	}
	// Initialize the repository only when it is provably absent (no retained
	// config object). Re-running init against an existing repository-format-v2
	// repository would fail because retained config is immutable, blocking every
	// point after the first.
	if _, statErr := os.Stat(filepath.Join(root, "config")); os.IsNotExist(statErr) {
		initRequest := base
		initRequest.Mode = "init"
		if _, err := adapterImpl.config.Runner.Run(ctx, initRequest, password); err != nil {
			return adapter.Effect{}, err
		}
	} else if statErr != nil {
		return adapter.Effect{}, backupError(generated.ErrorCodeIntegrityFailure, "local-backup-repository")
	}
	// The config is read through the same FD-relative, ownership-checked object
	// boundary that serves restic. A retained non-v2 repository blocks before
	// any backup write, including on the second and later points.
	if format, err := restServer.RepositoryFormat(); err != nil || format != 2 {
		return adapter.Effect{}, backupError(generated.ErrorCodeIntegrityFailure, "local-backup-format")
	}
	backupRequest := base
	backupRequest.Mode = "backup"
	backupRequest.SnapshotPath = snapshotPath
	result, err := adapterImpl.config.Runner.Run(ctx, backupRequest, password)
	if err != nil {
		return adapter.Effect{}, err
	}
	if result.RepositoryFormat != 2 {
		return adapter.Effect{}, backupError(generated.ErrorCodeIntegrityFailure, "local-backup-format")
	}

	inventory, err := enumerateRepository(root, adapterImpl.config.ExpectedUID)
	if err != nil || len(inventory) == 0 {
		return adapter.Effect{}, backupError(generated.ErrorCodeIntegrityFailure, "local-backup-inventory")
	}

	manifest := backup.CreationManifest{
		Schema: backup.CreationManifestSchema, SchemaVersion: backup.CreationManifestVersion,
		PolicyID: policy.PolicyID, PolicyDigest: policyDigest, PointID: pointID, RunID: binding.RunID, StepID: binding.StepID,
		RepositoryID: repositoryID, RepositoryClass: policy.RepositoryClass, SourceID: policy.SourceID,
		SourceSelectors: append([]string(nil), policy.SourceSelectors...), SourceRevision: capture.Snapshot.Revision.StateRevision,
		RecoveryEpoch: binding.RecoveryEpoch, ConsistencyHookID: policy.ConsistencyHookID, ConsistencySuccess: capture.Consistency.Success,
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

// admitCapacity forecasts retained bytes plus declared growth and headroom and
// blocks creation when the destination filesystem cannot hold it. It never prunes.
func admitCapacity(root string, policy generated.BackupPolicy) error {
	if policy.ExpectedBytes < 0 || policy.ExpectedGrowthBytes < 0 || policy.MinimumFreeBytes < 0 {
		return backupError(generated.ErrorCodeInputInvalid, "local-backup-capacity")
	}
	required := uint64(policy.ExpectedBytes)
	for _, part := range []int64{policy.ExpectedGrowthBytes, policy.MinimumFreeBytes} {
		if required > ^uint64(0)-uint64(part) {
			return backupError(generated.ErrorCodePrerequisiteBlocked, "local-backup-capacity")
		}
		required += uint64(part)
	}
	free, err := freeBytes(root)
	if err != nil {
		return backupError(generated.ErrorCodeIntegrityFailure, "local-backup-capacity")
	}
	if free < required {
		return backupError(generated.ErrorCodePrerequisiteBlocked, "local-backup-capacity")
	}
	return nil
}

func backupError(code, target string) error { return failure.New(code, target, false) }

// enumerateRepository lists the retained restic objects under the repository root
// (config plus keys/data/index/snapshots) and hashes each through FD-relative,
// symlink-refusing access, producing the exact expected inventory. Locks are
// mutable and excluded. Every object is confirmed a service-owned single-link
// regular file, so a swapped symlink, hardlink, or wrong-owner file cannot enter
// the durable inventory.
func enumerateRepository(root string, expectedUID uint32) ([]backup.ExpectedObject, error) {
	rootDescriptor, err := unix.Openat2(unix.AT_FDCWD, root, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, err
	}
	defer unix.Close(rootDescriptor)

	var inventory []backup.ExpectedObject
	if object, err := hashObjectAt(rootDescriptor, "config", "config", expectedUID); err == nil {
		inventory = append(inventory, object)
	}
	for _, objectType := range []string{"keys", "data", "index", "snapshots"} {
		typeDescriptor, err := unix.Openat(rootDescriptor, objectType, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			if errors.Is(err, unix.ENOENT) {
				continue
			}
			return nil, err
		}
		directory := os.NewFile(uintptr(typeDescriptor), objectType)
		if directory == nil {
			_ = unix.Close(typeDescriptor)
			return nil, errors.New("unsafe repository directory")
		}
		names, readErr := directory.Readdirnames(-1)
		if readErr != nil {
			_ = directory.Close()
			return nil, readErr
		}
		for _, name := range names {
			object, err := hashObjectAt(typeDescriptor, objectType, name, expectedUID)
			if err != nil {
				_ = directory.Close()
				return nil, err
			}
			inventory = append(inventory, object)
		}
		if err := directory.Close(); err != nil {
			return nil, err
		}
	}
	return inventory, nil
}

// hashObjectAt opens one object by name relative to an already-validated
// directory descriptor, refusing symlinks, and hashes the same descriptor after
// confirming it is a service-owned single-link regular file on a local filesystem.
func hashObjectAt(directoryDescriptor int, objectType, name string, expectedUID uint32) (backup.ExpectedObject, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") {
		return backup.ExpectedObject{}, errors.New("unsafe object name")
	}
	descriptor, err := unix.Openat(directoryDescriptor, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return backup.ExpectedObject{}, err
	}
	file := os.NewFile(uintptr(descriptor), name)
	if file == nil {
		_ = unix.Close(descriptor)
		return backup.ExpectedObject{}, errors.New("unsafe repository object")
	}
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(descriptor, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != expectedUID {
		return backup.ExpectedObject{}, errors.New("unsafe repository object")
	}
	hasher := sha256.New()
	written, err := io.Copy(hasher, file)
	if err != nil {
		return backup.ExpectedObject{}, err
	}
	return backup.ExpectedObject{Type: objectType, Name: name, Bytes: written, Digest: "sha256:" + hex.EncodeToString(hasher.Sum(nil))}, nil
}

func freeBytes(root string) (uint64, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(root, &stat); err != nil {
		return 0, err
	}
	return uint64(stat.Bavail) * uint64(stat.Bsize), nil
}
