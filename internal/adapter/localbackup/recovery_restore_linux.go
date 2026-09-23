//go:build linux

package localbackup

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	_ "github.com/ncruces/go-sqlite3/driver"
	"github.com/vegastack/vegastack-labs/internal/backup"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/recovery"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
	"golang.org/x/sys/unix"
)

const recoveryRestoreLifetime = 5 * time.Minute

// RecoveryCredentialRequest is the complete server-owned JIT read. A
// production source must re-read the active reference and applied capability
// before returning a borrowed value; the caller always closes the value.
type RecoveryCredentialRequest struct {
	ReferenceID, ConsumerID, PlanID, PlanDigest, RunID, StepID, LeaseID string
	StateRevision, RecoveryEpoch                                        int64
}

type RecoveryCredentialSource interface {
	BorrowRecoveryCredential(context.Context, RecoveryCredentialRequest) (*credentialref.Value, error)
}

type RecoveryRestoreConfig struct {
	LocalBackup  *serverconfig.LocalBackup
	ExpectedUID  uint32
	Backups      *store.BackupRepository
	Inspector    store.RestoredSQLiteInspector
	Credentials  RecoveryCredentialSource
	Trust        DependencyTrustVerifier
	Expectations store.OnlineSnapshotSource
	Clock        func() time.Time
}

type RecoverySnapshotResolver struct{ config RecoveryRestoreConfig }

func NewRecoverySnapshotResolver(config RecoveryRestoreConfig) (*RecoverySnapshotResolver, error) {
	if config.LocalBackup == nil || config.Backups == nil || config.Inspector == nil || config.Credentials == nil || config.Trust == nil || config.Expectations == nil || serverconfig.VerifyLocalBackup(config.LocalBackup, config.ExpectedUID) != nil {
		return nil, backupError(generated.ErrorCodePrerequisiteBlocked, "restore-local-runtime")
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	return &RecoverySnapshotResolver{config: config}, nil
}

func (resolver *RecoverySnapshotResolver) ResolveLocal(_ context.Context, source store.LocalRecoverySource) (recovery.SnapshotReader, error) {
	if resolver == nil || source.Point.PointID == "" || source.KeyReferenceID == "" {
		return nil, backupError(generated.ErrorCodePrerequisiteBlocked, "restore-local-snapshot")
	}
	return &recoverySnapshotReader{config: resolver.config, source: source}, nil
}

// RecoveryCompatibilityVerifier rechecks the current pinned runtime and
// independently applied dependency facts. Historical last-good proof alone is
// insufficient for a present restore.
type RecoveryCompatibilityVerifier struct{ config RecoveryRestoreConfig }

func NewRecoveryCompatibilityVerifier(config RecoveryRestoreConfig) (*RecoveryCompatibilityVerifier, error) {
	resolver, err := NewRecoverySnapshotResolver(config)
	if err != nil {
		return nil, err
	}
	return &RecoveryCompatibilityVerifier{config: resolver.config}, nil
}

func (verifier *RecoveryCompatibilityVerifier) VerifyRestoreCompatibility(ctx context.Context, selection recovery.SourceSelection, source store.LocalRecoverySource) error {
	var manifest backup.CreationManifest
	if verifier == nil || json.Unmarshal(source.Point.ManifestJSON, &manifest) != nil || manifest.PointID != source.Point.PointID || manifest.KeyReferenceID != source.KeyReferenceID || manifest.ResticDigest != pinnedResticDigest() || manifest.PlatformDigest != platformDigest() || manifest.CatalogDigest != source.CatalogDigest || manifest.DependencyInventoryDigest != source.DependencyDigest || backup.ExpectedDependencyInventoryDigest(manifest.ExpectedDependencies) != source.DependencyDigest {
		return backupError(generated.ErrorCodePrerequisiteBlocked, "restore-local-compatibility")
	}
	expected, err := verifier.config.Expectations.CurrentExpectation(ctx)
	if err != nil || expected.CatalogSHA256 != digestBytes(source.CatalogDigest) || expected.SchemaVersion != source.DatabaseSchemaVersion || selection.TargetSchemaVersion != stringUint(source.DatabaseSchemaVersion) {
		return backupError(generated.ErrorCodePrerequisiteBlocked, "restore-local-compatibility")
	}
	evidence, err := verifier.config.Trust.VerifyCurrent(ctx, DependencyTrustRequest{PointID: source.Point.PointID, PolicyDigest: source.Point.PolicyDigest, ResticDigest: manifest.ResticDigest, CatalogDigest: manifest.CatalogDigest, StateRevision: source.Verification.StateRevision, RecoveryEpoch: source.Verification.RecoveryEpoch, Expected: manifest.ExpectedDependencies})
	if err != nil || !exactDependencyTrust(manifest.ExpectedDependencies, evidence, source.Verification.StateRevision, source.Verification.RecoveryEpoch) {
		return backupError(generated.ErrorCodePrerequisiteBlocked, "restore-local-dependency-trust")
	}
	boundDependencies := make([]generated.RestoreDependencyBinding, len(source.Verification.DependencyTrust))
	for index, proof := range source.Verification.DependencyTrust {
		boundDependencies[index] = generated.RestoreDependencyBinding{DependencyID: proof.DependencyID, Kind: proof.Kind, Digest: proof.Digest}
	}
	if !exactRestoreDependencies(manifest.ExpectedDependencies, boundDependencies) ||
		selection.TargetReleaseBuildID == "" || selection.TargetToolVersion == "" || selection.TargetSchemaVersion == "" {
		return backupError(generated.ErrorCodePrerequisiteBlocked, "restore-local-target-compatibility")
	}
	return nil
}

func exactRestoreDependencies(expected []backup.ExpectedDependency, required []generated.RestoreDependencyBinding) bool {
	if len(expected) == 0 || len(expected) != len(required) {
		return false
	}
	want := make(map[string]backup.ExpectedDependency, len(expected))
	for _, dependency := range expected {
		key := dependency.Kind + "\x00" + dependency.DependencyID
		if dependency.DependencyID == "" || dependency.Kind == "" || dependency.Digest == "" || want[key].DependencyID != "" {
			return false
		}
		want[key] = dependency
	}
	for _, dependency := range required {
		key := dependency.Kind + "\x00" + dependency.DependencyID
		value, ok := want[key]
		if !ok || value.Digest != dependency.Digest {
			return false
		}
		delete(want, key)
	}
	return len(want) == 0
}

type RecoveryAuditVerifier struct{}

func (RecoveryAuditVerifier) VerifyRestoreAuditPosition(ctx context.Context, source store.LocalRecoverySource, reader recovery.SnapshotReader) (recovery.AuditContinuity, error) {
	if reader == nil {
		return recovery.AuditContinuity{}, backupError(generated.ErrorCodePrerequisiteBlocked, "restore-local-audit")
	}
	position, err := reader.InspectAudit(ctx)
	if err != nil || position.LocalLastEventID < 0 || position.IndependentLastEventID != position.LocalLastEventID || position.IndependentCheckpointDigest == "" {
		return recovery.AuditContinuity{}, backupError(generated.ErrorCodePrerequisiteBlocked, "restore-local-audit")
	}
	return position, nil
}

type recoverySnapshotReader struct {
	config RecoveryRestoreConfig
	source store.LocalRecoverySource
}

func (reader *recoverySnapshotReader) InspectAudit(ctx context.Context) (recovery.AuditContinuity, error) {
	var result recovery.AuditContinuity
	err := reader.withRestored(ctx, "restore-preflight-"+reader.source.Verification.VerificationID, reader.source.Verification.ProofDigest, "preflight-run-"+reader.source.Point.PointID, "preflight-step", "preflight-lease-"+randomHex(12), func(path string) error {
		position, err := readRestoredAuditPosition(ctx, path)
		result = position
		return err
	})
	return result, err
}

func (reader *recoverySnapshotReader) Restore(ctx context.Context, target recovery.CandidateTarget, binding generated.RestoreBinding) (recovery.SnapshotReceipt, error) {
	path, ok := recovery.CandidateTargetPath(target)
	if !ok || binding.PointID != reader.source.Point.PointID || binding.Source.KeyReferenceID != reader.source.KeyReferenceID || binding.RecoveryRunID == "" || binding.RecoveryStepID == "" || binding.RecoveryLeaseID == "" {
		return recovery.SnapshotReceipt{}, backupError(generated.ErrorCodePlanStale, "restore-local-binding")
	}
	var bytes int64
	err := reader.withRestored(ctx, binding.PlanID, binding.PlanDigest, binding.RecoveryRunID, binding.RecoveryStepID, binding.RecoveryLeaseID, func(restored string) error {
		var err error
		bytes, err = copyRestoredCandidate(restored, path, reader.config.ExpectedUID)
		return err
	})
	if err != nil {
		return recovery.SnapshotReceipt{}, err
	}
	return recovery.SnapshotReceipt{PointID: reader.source.Point.PointID, SnapshotID: reader.source.SnapshotID, ContentDigest: reader.source.Point.ContentDigest, Bytes: bytes}, nil
}

func (reader *recoverySnapshotReader) withRestored(ctx context.Context, planID, planDigest, runID, stepID, leaseID string, use func(string) error) (outcomeErr error) {
	if ctx == nil || use == nil || planID == "" || planDigest == "" || runID == "" || stepID == "" || leaseID == "" {
		return backupError(generated.ErrorCodePrerequisiteBlocked, "restore-local-runtime")
	}
	var manifest backup.CreationManifest
	if json.Unmarshal(reader.source.Point.ManifestJSON, &manifest) != nil || manifest.PointID != reader.source.Point.PointID || manifest.SnapshotID != reader.source.SnapshotID || manifest.ContentDigest != reader.source.Point.ContentDigest || manifest.KeyReferenceID != reader.source.KeyReferenceID || manifest.ResticDigest != pinnedResticDigest() || manifest.PlatformDigest != platformDigest() {
		return backupError(generated.ErrorCodeIntegrityFailure, "restore-local-manifest")
	}
	objects := append([]backup.ExpectedObject(nil), manifest.ExpectedObjects...)
	inventoryDigest := manifest.InventoryDigest
	if successor, err := reader.config.Backups.GetLocalRetirementSuccessorForPoint(ctx, manifest.PointID); err == nil {
		objects = make([]backup.ExpectedObject, len(successor.Objects))
		for i, object := range successor.Objects {
			objects[i] = backup.ExpectedObject{Type: object.Type, Name: object.Name, Bytes: object.Bytes, Digest: object.Digest}
		}
		inventoryDigest = successor.SuccessorInventoryDigest
	} else if store.Code(err) != generated.ErrorCodeResourceNotFound {
		return err
	}
	now := reader.config.Clock().UTC()
	deadline := now.Add(recoveryRestoreLifetime)
	readLeaseID := leaseID
	lease := store.BackupReadLeaseRequest{LeaseID: readLeaseID, PointID: manifest.PointID, RepositoryID: manifest.RepositoryID, RepositoryClass: manifest.RepositoryClass, SourceRevision: manifest.SourceRevision, Expected: store.RevisionToken{StateRevision: reader.source.Verification.StateRevision, RecoveryEpoch: manifest.RecoveryEpoch}, MaximumExpiresAt: deadline}
	if err := reader.config.Backups.AcquireBackupReadLease(ctx, lease); err != nil {
		return err
	}
	defer func() {
		if err := reader.config.Backups.ReleaseBackupReadLease(context.WithoutCancel(ctx), readLeaseID); err != nil {
			outcomeErr = backupError(generated.ErrorCodeRecoveryRequired, "restore-local-read-lease-release")
		}
	}()
	policy, err := backup.LoadCustodyPolicy(reader.config.LocalBackup.CustodyPolicyPath)
	if err != nil || policy.ControllerUID != reader.config.ExpectedUID {
		return backupError(generated.ErrorCodeIntegrityFailure, "restore-local-custody-policy")
	}
	read := backup.ReadLease{LeaseID: readLeaseID, PointID: manifest.PointID, RepositoryID: manifest.RepositoryID, RecoveryEpoch: manifest.RecoveryEpoch, MaximumExpiresAt: deadline}
	session := backup.CustodySession{ProtocolVersion: backup.CustodyProtocolVersion, Role: "verifier", PlanID: planID, PlanDigest: planDigest, RunID: runID, StepID: stepID, LeaseID: readLeaseID, RepositoryID: manifest.RepositoryID, RepositoryClass: manifest.RepositoryClass, PointID: manifest.PointID, SourceID: manifest.SourceID, SourceRevision: manifest.SourceRevision, RecoveryEpoch: manifest.RecoveryEpoch, MaximumExpiresAt: deadline, MaximumObjects: int64(len(objects)) + 100000, MaximumBytes: totalBytes(objects) + 1<<30, ReadLease: &read}
	launcher := backup.CustodyLauncher{PolicyPath: reader.config.LocalBackup.CustodyPolicyPath, Reader: &readLeaseVerifier{backups: reader.config.Backups, request: lease}, Journal: &custodyJournal{backups: reader.config.Backups, read: &lease}, Clock: reader.config.Clock}
	custody, err := launcher.Start(ctx, session)
	if err != nil {
		return backupError(generated.ErrorCodePrerequisiteBlocked, "restore-local-custody")
	}
	defer func() {
		if err := custody.Close(context.WithoutCancel(ctx)); err != nil {
			outcomeErr = backupError(generated.ErrorCodeRecoveryRequired, "restore-local-custody-close")
		}
	}()
	value, err := reader.config.Credentials.BorrowRecoveryCredential(ctx, RecoveryCredentialRequest{ReferenceID: reader.source.KeyReferenceID, ConsumerID: AdapterID, PlanID: planID, PlanDigest: planDigest, RunID: runID, StepID: stepID, LeaseID: leaseID, StateRevision: reader.source.Verification.StateRevision, RecoveryEpoch: manifest.RecoveryEpoch})
	if err != nil || value == nil || len(value.Bytes()) == 0 {
		if value != nil {
			value.Close()
		}
		return backupError(generated.ErrorCodePrerequisiteBlocked, "restore-local-credential")
	}
	defer value.Close()
	observed, err := custody.InventoryExpected(ctx, objects)
	if err != nil {
		return backupError(generated.ErrorCodeIntegrityFailure, "restore-local-inventory")
	}
	if inventoryDigest == manifest.InventoryDigest {
		_, err = backup.VerifyCustodyInventory(manifest, reader.source.Point.ManifestDigest, observed)
	} else {
		_, err = backup.VerifySuccessorCustodyInventory(manifest, reader.source.Point.ManifestDigest, manifest.InventoryDigest, inventoryDigest, objects, observed)
	}
	if err != nil {
		return backupError(generated.ErrorCodeIntegrityFailure, "restore-local-inventory")
	}
	root, ok := recoveryRepositoryRoot(reader.config.LocalBackup, manifest.RepositoryClass)
	if !ok {
		return backupError(generated.ErrorCodePrerequisiteBlocked, "restore-local-repository")
	}
	base := backup.ResticRequest{BinaryPath: reader.config.LocalBackup.ResticBinaryPath, Architecture: runtime.GOARCH, RepositoryURL: custody.RepositoryURL(), RepositoryID: manifest.RepositoryID, RepositoryClass: manifest.RepositoryClass, RepositoryRoot: root, ExchangeRoot: policy.ExchangeRoot, PolicyDigest: manifest.PolicyDigest, ExecutionUID: policy.ResticUID, ExecutionGID: policy.ResticUID, ControllerUID: policy.ControllerUID}
	snapshots := base
	snapshots.Mode = "snapshots"
	snapshots.OutputLimit = 4 << 20
	listed, err := custody.RunRestic(ctx, snapshots, value)
	if err != nil || listed.RepositoryFormat != 2 || len(listed.SnapshotPaths[manifest.SnapshotID]) != 1 {
		return backupError(generated.ErrorCodeIntegrityFailure, "restore-local-snapshot")
	}
	check := base
	check.Mode = "check-full"
	check.OutputLimit = 4 << 20
	checked, err := custody.RunRestic(ctx, check, value)
	if err != nil || checked.RepositoryFormat != 2 {
		return backupError(generated.ErrorCodeIntegrityFailure, "restore-local-full-read")
	}
	// The custody broker accepts only this fixed server-owned exchange class and
	// returns the complete restored tree to the controller UID before use.
	temp, err := os.MkdirTemp(policy.ExchangeRoot, ".vsk-backup-verify-")
	if err != nil {
		return err
	}
	defer func() {
		if err := os.RemoveAll(temp); err != nil {
			outcomeErr = backupError(generated.ErrorCodeRecoveryRequired, "restore-local-cleanup")
		}
	}()
	restore := base
	restore.Mode = "restore"
	restore.SnapshotID = manifest.SnapshotID
	restore.RestoreTarget = temp
	restore.OutputLimit = 4 << 20
	restored, err := custody.RunRestic(ctx, restore, value)
	if err != nil || restored.RepositoryFormat != 2 {
		return backupError(generated.ErrorCodeIntegrityFailure, "restore-local-restore")
	}
	captured := listed.SnapshotPaths[manifest.SnapshotID][0]
	if !safeRecoveryCapturedPath(captured, policy.ExchangeRoot) {
		return backupError(generated.ErrorCodeIntegrityFailure, "restore-local-path")
	}
	restoredPath := filepath.Join(temp, strings.TrimPrefix(captured, string(filepath.Separator)))
	digest, err := hashRecoveryFile(restoredPath, policy.ControllerUID)
	if err != nil || digest != manifest.ContentDigest {
		return backupError(generated.ErrorCodeIntegrityFailure, "restore-local-content")
	}
	catalog := digestBytes(manifest.CatalogDigest)
	expected := store.SnapshotExpectation{SchemaVersion: manifest.DatabaseSchemaVersion, Revision: store.RevisionToken{StateRevision: manifest.SourceRevision, RecoveryEpoch: manifest.RecoveryEpoch}, CatalogSHA256: catalog}
	owner, ok := reader.config.Inspector.(store.RestoredSQLiteOwnerInspector)
	if !ok {
		return backupError(generated.ErrorCodePrerequisiteBlocked, "restore-local-inspector")
	}
	inspection, err := owner.InspectSnapshotOwned(ctx, restoredPath, expected, policy.ControllerUID)
	if err != nil || inspection.IntegrityStatus != store.IntegrityVerified || inspection.Revision != expected.Revision || inspection.SchemaVersion != expected.SchemaVersion {
		return backupError(generated.ErrorCodeIntegrityFailure, "restore-local-sqlite")
	}
	if err := reader.config.Backups.VerifyActiveReadLease(ctx, lease, reader.config.Clock()); err != nil {
		return err
	}
	return use(restoredPath)
}

func recoveryRepositoryRoot(profile *serverconfig.LocalBackup, class string) (string, bool) {
	if profile == nil {
		return "", false
	}
	if class == "standard" {
		return profile.StandardRoot, profile.StandardRoot != ""
	}
	if class == "critical" {
		return profile.CriticalRoot, profile.CriticalRoot != ""
	}
	return "", false
}
func digestBytes(value string) [32]byte {
	var out [32]byte
	raw, _ := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	copy(out[:], raw)
	return out
}
func stringUint(value uint64) string {
	if value == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for value > 0 {
		i--
		b[i] = byte('0' + value%10)
		value /= 10
	}
	return string(b[i:])
}
func safeRecoveryCapturedPath(path, exchange string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && filepath.Base(path) == "database.sqlite" && filepath.Dir(filepath.Dir(path)) == exchange && strings.HasPrefix(filepath.Base(filepath.Dir(path)), ".vsk-backup-staging-")
}
func hashRecoveryFile(path string, uid uint32) (string, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	f := os.NewFile(uintptr(fd), "restored")
	if f == nil {
		_ = unix.Close(fd)
		return "", errors.New("invalid restored file descriptor")
	}
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != uid {
		return "", errors.New("unsafe restored file")
	}
	h := sha256.New()
	_, err = io.Copy(h, f)
	if err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
func copyRestoredCandidate(source, target string, uid uint32) (int64, error) {
	inFD, err := unix.Open(source, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return 0, err
	}
	in := os.NewFile(uintptr(inFD), "restored")
	if in == nil {
		_ = unix.Close(inFD)
		return 0, errors.New("invalid restored file descriptor")
	}
	defer in.Close()
	var sourceStat unix.Stat_t
	if unix.Fstat(inFD, &sourceStat) != nil || sourceStat.Mode&unix.S_IFMT != unix.S_IFREG || sourceStat.Nlink != 1 || sourceStat.Uid != uid {
		return 0, errors.New("unsafe restored file")
	}
	fd, err := unix.Open(target, unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return 0, err
	}
	out := os.NewFile(uintptr(fd), "candidate")
	defer out.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != uid {
		return 0, errors.New("unsafe candidate")
	}
	if err := unix.Ftruncate(fd, 0); err != nil {
		return 0, err
	}
	n, err := io.Copy(out, in)
	if err == nil {
		err = out.Sync()
	}
	return n, err
}
func readRestoredAuditPosition(ctx context.Context, path string) (recovery.AuditContinuity, error) {
	u := url.URL{Scheme: "file", Path: path}
	q := u.Query()
	q.Set("mode", "ro")
	q.Set("immutable", "1")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite3", u.String())
	if err != nil {
		return recovery.AuditContinuity{}, err
	}
	defer db.Close()
	var local int64
	if err = db.QueryRowContext(ctx, `SELECT COALESCE(MAX(event_id),0) FROM audit_chain_links`).Scan(&local); err != nil {
		return recovery.AuditContinuity{}, err
	}
	var raw []byte
	err = db.QueryRowContext(ctx, `SELECT canonical_bytes FROM audit_checkpoints WHERE status='anchored' AND independent_read_digest IS NOT NULL ORDER BY last_event_id DESC LIMIT 1`).Scan(&raw)
	var checkpoint generated.AuditCheckpoint
	if err != nil || json.Unmarshal(raw, &checkpoint) != nil || generated.ValidateContractJSON(generated.SchemaIDAuditCheckpoint, raw, generated.ContractExact) != nil || checkpoint.Status != "anchored" || checkpoint.VerificationStatus != "verified" || checkpoint.IndependentReadDigest == nil {
		return recovery.AuditContinuity{}, err
	}
	if checkpoint.LastEventID != local || len(*checkpoint.IndependentReadDigest) != 71 {
		return recovery.AuditContinuity{}, errors.New("audit head is not independently anchored")
	}
	return recovery.AuditContinuity{LocalLastEventID: local, IndependentLastEventID: checkpoint.LastEventID, IndependentCheckpointDigest: *checkpoint.IndependentReadDigest}, nil
}
