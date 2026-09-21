//go:build linux

package localbackup

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/backup"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// executeBoundVerify uses the same exact-plan credential boundary as creation.
// The point remains immutable; a separate attempt records each verification.
func (adapterImpl *Adapter) executeBoundVerify(ctx context.Context, operation adapter.Operation, binding adapter.ExactExecutionBinding, values []*credentialref.Value) (effect adapter.Effect, effectErr error) {
	if operation.AdapterID != AdapterID || len(values) != 1 || values[0] == nil || adapterImpl.config.Inspector == nil ||
		operation.TargetID == "" || binding.RunID == "" || binding.StepID == "" {
		return adapter.Effect{}, backupError(generated.ErrorCodePrerequisiteBlocked, "local-backup-verify-binding")
	}
	policy, policyDigest, err := adapterImpl.resolvePolicy(ctx, binding)
	if err != nil {
		return adapter.Effect{}, err
	}
	point, err := adapterImpl.config.Backups.GetPendingRecoveryPoint(ctx, operation.TargetID)
	if err != nil {
		return adapter.Effect{}, err
	}
	if point.PolicyID != policy.PolicyID || point.PolicyDigest != policyDigest || point.RepositoryClass != policy.RepositoryClass ||
		policy.RepositoryID == nil || point.RepositoryID != *policy.RepositoryID || point.RecoveryEpoch != binding.RecoveryEpoch ||
		point.SourceRevision != binding.StateRevision || operation.InputDigest != point.ManifestDigest ||
		operation.ArtifactDigest != point.InventoryDigest || policy.EncryptionKeyReferenceID == nil ||
		len(operation.SecretReferences) != 1 || operation.SecretReferences[0].ID != *policy.EncryptionKeyReferenceID {
		return adapter.Effect{}, backupError(generated.ErrorCodePlanStale, "local-backup-verify-binding")
	}
	if !backupProfileMatches(adapterImpl.config.LocalBackup, policy) ||
		serverconfig.VerifyLocalBackup(adapterImpl.config.LocalBackup, adapterImpl.config.ExpectedUID) != nil {
		return adapter.Effect{}, backupError(generated.ErrorCodeIntegrityFailure, "local-backup-verify-profile")
	}
	root, ok := adapterImpl.repositoryRoot(point.RepositoryClass)
	if !ok {
		return adapter.Effect{}, backupError(generated.ErrorCodePrerequisiteBlocked, "local-backup-verify-repository")
	}
	var manifest backup.CreationManifest
	if json.Unmarshal(point.ManifestJSON, &manifest) != nil || manifest.PointID != point.PointID ||
		manifest.PolicyDigest != point.PolicyDigest || manifest.InventoryDigest != point.InventoryDigest ||
		manifest.ContentDigest != point.ContentDigest || manifest.RepositoryID != point.RepositoryID {
		return adapter.Effect{}, backupError(generated.ErrorCodeIntegrityFailure, "local-backup-verify-manifest")
	}
	deadline, err := time.Parse(time.RFC3339, binding.MaximumExpiresAt)
	if err != nil || !adapterImpl.config.Clock().Before(deadline) {
		return adapter.Effect{}, backupError(generated.ErrorCodePlanStale, "local-backup-verify-deadline")
	}
	leaseID := "backup-read-" + randomHex(16)
	leaseRequest := store.BackupReadLeaseRequest{LeaseID: leaseID, PointID: point.PointID,
		RepositoryID: point.RepositoryID, RepositoryClass: point.RepositoryClass, SourceRevision: point.SourceRevision,
		Expected: store.RevisionToken{StateRevision: binding.StateRevision, RecoveryEpoch: binding.RecoveryEpoch}, MaximumExpiresAt: deadline}
	if err := adapterImpl.config.Backups.AcquireBackupReadLease(ctx, leaseRequest); err != nil {
		return adapter.Effect{}, err
	}
	defer func() {
		if err := adapterImpl.config.Backups.ReleaseBackupReadLease(context.WithoutCancel(ctx), leaseID); err != nil {
			effect = adapter.Effect{EffectObserved: true}
			effectErr = backupError(generated.ErrorCodeRecoveryRequired, "local-backup-read-lease-release")
		}
	}()
	readLease := backup.ReadLease{LeaseID: leaseID, PointID: point.PointID, RepositoryID: point.RepositoryID,
		RecoveryEpoch: binding.RecoveryEpoch, MaximumExpiresAt: deadline}
	server, err := backup.NewVerifierRESTServer(root, adapterImpl.config.ExpectedUID, readLease,
		&readLeaseVerifier{backups: adapterImpl.config.Backups, request: leaseRequest}, adapterImpl.config.Clock)
	if err != nil {
		return adapter.Effect{}, backupError(generated.ErrorCodeIntegrityFailure, "local-backup-verify-rest")
	}
	socketDir, err := os.MkdirTemp(filepath.Dir(root), ".vsk-backup-verify-socket-")
	if err != nil {
		return adapter.Effect{}, backupError(generated.ErrorCodeIntegrityFailure, "local-backup-verify-socket")
	}
	defer os.RemoveAll(socketDir)
	listener, err := net.Listen("unix", filepath.Join(socketDir, "rest.sock"))
	if err != nil {
		return adapter.Effect{}, backupError(generated.ErrorCodeIntegrityFailure, "local-backup-verify-socket")
	}
	defer listener.Close()
	serveCtx, cancelServe := context.WithCancel(ctx)
	defer cancelServe()
	go func() { _ = server.Serve(serveCtx, listener) }()

	proofClass := "fixture"
	if adapterImpl.config.LiveProof {
		proofClass = "live"
	}
	attempt := store.LocalVerificationRequest{VerificationID: "backup-verification-" + randomHex(16), RunID: binding.RunID, PointID: point.PointID,
		ReadLeaseID: leaseID, ManifestDigest: point.ManifestDigest, InventoryDigest: point.InventoryDigest,
		ObservedDigest: point.InventoryDigest, ContentDigest: point.ContentDigest, CatalogDigest: manifest.CatalogDigest,
		DependencyDigest: manifest.DependencyInventoryDigest, KeyReferenceID: manifest.KeyReferenceID,
		SourceRevision: point.SourceRevision, Expected: leaseRequest.Expected, ProofClass: proofClass,
		Result: "failed", ReasonCode: "INTEGRITY_FAILURE"}
	defer func() {
		// A failed verification still leaves an append-only attempt. If the epoch
		// changed, the store rejects it; the run engine records the stale failure.
		if attempt.Result != "passed" {
			_, _ = adapterImpl.config.Backups.AppendLocalVerification(context.WithoutCancel(ctx), attempt)
		}
	}()
	inventory, err := backup.VerifyLocalInventory(ctx, manifest, point.ManifestDigest, server)
	if err != nil {
		return adapter.Effect{}, backupError(generated.ErrorCodeIntegrityFailure, "local-backup-verify-inventory")
	}
	base := backup.ResticRequest{BinaryPath: adapterImpl.config.LocalBackup.ResticBinaryPath, Architecture: runtime.GOARCH,
		RepositoryURL: "http+unix://" + listener.Addr().String() + ":/" + point.RepositoryID + "/",
		RepositoryID:  point.RepositoryID, RepositoryClass: point.RepositoryClass, RepositoryRoot: root,
		PolicyDigest: policyDigest}
	functional, err := backup.VerifyFunctionalRestore(ctx, inventory, manifest, adapterImpl.config.Runner, base, values[0], adapterImpl.config.Inspector)
	if err != nil {
		return adapter.Effect{}, backupError(generated.ErrorCodeIntegrityFailure, "local-backup-verify-functional")
	}
	if err := adapterImpl.config.Backups.VerifyActiveReadLease(ctx, leaseRequest, adapterImpl.config.Clock()); err != nil {
		return adapter.Effect{}, err
	}
	attempt.Result, attempt.ReasonCode = "passed", ""
	attempt.ObservedDigest = inventory.ObservedDigest
	attempt.FullReadAt, attempt.FunctionalRestoredAt = functional.FullReadAt, functional.FunctionalRestoredAt
	receipt, err := adapterImpl.config.Backups.AppendLocalVerification(ctx, attempt)
	if err != nil {
		return adapter.Effect{}, err
	}
	if proofClass == "live" {
		previous, err := adapterImpl.config.Backups.CurrentLocalLastGood(ctx, point.RepositoryClass)
		if err != nil {
			return adapter.Effect{EffectObserved: true}, err
		}
		if err := adapterImpl.config.Backups.AdvanceLocalLastGood(ctx, receipt, leaseRequest.Expected, previous); err != nil {
			return adapter.Effect{EffectObserved: true}, err
		}
	}
	return adapter.Effect{Status: "succeeded", ResultDigest: receipt.ProofDigest, PendingPointID: &point.PointID,
		Changed: true, EffectObserved: true}, nil
}

func backupProfileMatches(profile *serverconfig.LocalBackup, policy generated.BackupPolicy) bool {
	if profile == nil || profile.SourceID != policy.SourceID || policy.RepositoryID == nil {
		return false
	}
	switch policy.RepositoryClass {
	case "standard":
		return profile.StandardRepositoryID == *policy.RepositoryID
	case "critical":
		return profile.CriticalRepositoryID == *policy.RepositoryID
	default:
		return false
	}
}

type readLeaseVerifier struct {
	backups *store.BackupRepository
	request store.BackupReadLeaseRequest
}

func (verifier *readLeaseVerifier) VerifyReadLease(lease backup.ReadLease, now time.Time) error {
	if lease.LeaseID != verifier.request.LeaseID || lease.PointID != verifier.request.PointID ||
		lease.RepositoryID != verifier.request.RepositoryID || lease.RecoveryEpoch != verifier.request.Expected.RecoveryEpoch {
		return backupError(generated.ErrorCodePlanStale, "local-backup-read-lease")
	}
	return verifier.backups.VerifyActiveReadLease(context.Background(), verifier.request, now)
}
