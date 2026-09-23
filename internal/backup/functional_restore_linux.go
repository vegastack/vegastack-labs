//go:build linux

package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/store"
	"golang.org/x/sys/unix"
)

type FunctionalRestoreProof struct {
	PointID, SnapshotID, ManifestDigest, InventoryDigest, ContentDigest, CatalogDigest string
	StateRevision, RecoveryEpoch                                                       int64
	FullReadAt, FunctionalRestoredAt                                                   time.Time
}

// VerifyFunctionalRestore runs the pinned child only through a read-leased REST
// boundary, proves the exact snapshot exists, reads every pack, restores into a
// fresh owner-only sibling of the repository and inspects the recovered SQLite
// copy. It never opens the authoritative database for writing.
func VerifyFunctionalRestore(ctx context.Context, inventory LocalInventoryProof, manifest CreationManifest,
	runner ResticRunner, base ResticRequest, password *credentialref.Value, inspector store.RestoredSQLiteInspector) (proof FunctionalRestoreProof, outcomeErr error) {
	invalid := errors.New("local functional restore failed")
	if runner == nil || password == nil || inspector == nil || inventory.PointID != manifest.PointID ||
		inventory.SnapshotID != manifest.SnapshotID || inventory.InventoryDigest != manifest.InventoryDigest ||
		inventory.ObservedDigest != manifest.InventoryDigest || inventory.RecoveryEpoch != manifest.RecoveryEpoch ||
		base.RepositoryID != manifest.RepositoryID || base.RepositoryClass != manifest.RepositoryClass || !filepath.IsAbs(base.RepositoryRoot) {
		return proof, invalid
	}
	snapshotsRequest := base
	snapshotsRequest.Mode = "snapshots"
	snapshotsRequest.OutputLimit = 4 << 20
	snapshots, err := runner.Run(ctx, snapshotsRequest, password)
	if err != nil || snapshots.RepositoryFormat != 2 {
		return proof, invalid
	}
	paths, exists := snapshots.SnapshotPaths[manifest.SnapshotID]
	if !exists || len(paths) != 1 || !safeCapturedSnapshotPath(paths[0], base.RepositoryRoot) {
		return proof, invalid
	}
	checkRequest := base
	checkRequest.Mode = "check-full"
	checkRequest.OutputLimit = 4 << 20
	check, err := runner.Run(ctx, checkRequest, password)
	if err != nil || check.RepositoryFormat != 2 {
		return proof, invalid
	}
	target, err := os.MkdirTemp(filepath.Dir(base.RepositoryRoot), ".vsk-backup-verify-")
	if err != nil {
		return proof, invalid
	}
	if base.ExecutionUID != 0 || base.ExecutionGID != 0 {
		if os.Geteuid() != 0 || base.ExecutionUID == 0 || base.ExecutionGID == 0 ||
			os.Chown(target, int(base.ExecutionUID), int(base.ExecutionGID)) != nil || os.Chmod(target, 0o700) != nil {
			return proof, invalid
		}
	}
	defer func() {
		if cleanupErr := os.RemoveAll(target); cleanupErr != nil {
			proof, outcomeErr = FunctionalRestoreProof{}, invalid
		}
	}()
	restoreRequest := base
	restoreRequest.Mode = "restore"
	restoreRequest.SnapshotID = manifest.SnapshotID
	restoreRequest.RestoreTarget = target
	restoreRequest.OutputLimit = 4 << 20
	restored, err := runner.Run(ctx, restoreRequest, password)
	if err != nil || restored.RepositoryFormat != 2 {
		return proof, invalid
	}
	relative := strings.TrimPrefix(paths[0], string(filepath.Separator))
	restoredPath := filepath.Join(target, relative)
	expectedUID := uint32(os.Geteuid())
	if base.ExecutionUID != 0 {
		expectedUID = base.ExecutionUID
	}
	contentDigest, err := hashRestoredSQLite(restoredPath, expectedUID)
	if err != nil || contentDigest != manifest.ContentDigest {
		return proof, invalid
	}
	catalogBytes, err := hex.DecodeString(strings.TrimPrefix(manifest.CatalogDigest, "sha256:"))
	if err != nil || len(catalogBytes) != sha256.Size {
		return proof, invalid
	}
	var catalog [32]byte
	copy(catalog[:], catalogBytes)
	expected := store.SnapshotExpectation{SchemaVersion: manifest.DatabaseSchemaVersion,
		Revision: store.RevisionToken{StateRevision: manifest.SourceRevision, RecoveryEpoch: manifest.RecoveryEpoch}, CatalogSHA256: catalog}
	var inspection store.SnapshotInspection
	if base.ExecutionUID != 0 {
		ownerInspector, ok := inspector.(store.RestoredSQLiteOwnerInspector)
		if !ok {
			return proof, invalid
		}
		inspection, err = ownerInspector.InspectSnapshotOwned(ctx, restoredPath, expected, base.ExecutionUID)
	} else {
		inspection, err = inspector.InspectSnapshot(ctx, restoredPath, expected)
	}
	if err != nil || inspection.IntegrityStatus != store.IntegrityVerified || inspection.Revision != expected.Revision || inspection.SchemaVersion != expected.SchemaVersion {
		return proof, invalid
	}
	return FunctionalRestoreProof{PointID: manifest.PointID, SnapshotID: manifest.SnapshotID, ManifestDigest: inventory.ManifestDigest,
		InventoryDigest: inventory.InventoryDigest, ContentDigest: contentDigest, CatalogDigest: manifest.CatalogDigest,
		StateRevision: manifest.SourceRevision, RecoveryEpoch: manifest.RecoveryEpoch,
		FullReadAt: check.CompletedAt, FunctionalRestoredAt: restored.CompletedAt}, nil
}

func safeCapturedSnapshotPath(path, repositoryRoot string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) != "database.sqlite" {
		return false
	}
	stage := filepath.Dir(path)
	return filepath.Dir(stage) == filepath.Dir(repositoryRoot) && strings.HasPrefix(filepath.Base(stage), ".vsk-backup-staging-")
}

func hashRestoredSQLite(path string, expectedUID ...uint32) (string, error) {
	descriptor, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return "", err
	}
	file := os.NewFile(uintptr(descriptor), "restored-sqlite")
	if file == nil {
		_ = unix.Close(descriptor)
		return "", errors.New("restored file unavailable")
	}
	defer file.Close()
	var stat unix.Stat_t
	owner := uint32(os.Geteuid())
	if len(expectedUID) == 1 {
		owner = expectedUID[0]
	}
	if unix.Fstat(descriptor, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != owner || !isLocalDescriptor(descriptor) {
		return "", errors.New("unsafe restored file")
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(hasher.Sum(nil)), nil
}
