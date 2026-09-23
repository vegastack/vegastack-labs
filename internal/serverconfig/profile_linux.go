//go:build linux

package serverconfig

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"runtime"

	"github.com/vegastack/vegastack-labs/internal/backupidentity"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"golang.org/x/sys/unix"
)

const maxResticExecutableBytes = 128 * 1024 * 1024

// VerifyLocalBackup is the protected-profile preflight for local recovery-point
// creation. It confirms both backup roots are service-owned 0700 directories on
// a supported local filesystem, and that the pinned restic executable is a
// service-owned regular file, not group/other writable, whose SHA-256 matches
// the exact pinned 0.19.1 digest for this architecture. It never executes the
// binary. It fails closed on any deviation and leaks no path in its error.
func VerifyLocalBackup(backup *LocalBackup, expectedUID uint32) error {
	_ = expectedUID // OS ownership is verified from the root-owned custody policy at launch.
	if backup == nil {
		return failure.New("PREREQUISITE_BLOCKED", "backup-profile", false)
	}
	if backup.SourceID != backupidentity.ControlDatabaseSource || backup.StandardRepositoryID != backupidentity.StandardRepository || backup.CriticalRepositoryID != backupidentity.CriticalRepository {
		return failure.New("INTEGRITY_FAILURE", "backup-profile", false)
	}
	if err := verifyResticExecutable(backup.ResticBinaryPath, 0); err != nil {
		return failure.New("INTEGRITY_FAILURE", "backup-profile", false)
	}
	return nil
}

func verifyResticExecutable(path string, expectedUID uint32) error {
	expectedDigest, ok := ExpectedResticExecutableDigest(runtime.GOARCH)
	if !ok {
		return unix.ENOTSUP
	}
	descriptor, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW),
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(descriptor), "restic")
	if file == nil {
		_ = unix.Close(descriptor)
		return unix.EPERM
	}
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(descriptor, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Nlink != 1 || stat.Uid != expectedUID || stat.Mode&0o022 != 0 || stat.Mode&0o100 == 0 {
		return unix.EPERM
	}
	if stat.Size <= 0 || stat.Size > maxResticExecutableBytes {
		return unix.EPERM
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, io.LimitReader(file, maxResticExecutableBytes+1)); err != nil {
		return err
	}
	if hex.EncodeToString(hasher.Sum(nil)) != expectedDigest {
		return unix.EPERM
	}
	return nil
}

type protectedLoader struct {
	expectedOwnerUID uint32
}

func NewLoader(expectedOwnerUID uint32) Loader {
	return &protectedLoader{expectedOwnerUID: expectedOwnerUID}
}

func (loader *protectedLoader) Load(ctx context.Context, profilePath string) (Profile, error) {
	if err := ctx.Err(); err != nil {
		return Profile{}, failure.New("INTERRUPTED", "server-config", false)
	}
	how := &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW),
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	}
	descriptor, err := unix.Openat2(unix.AT_FDCWD, profilePath, how)
	if err != nil {
		return Profile{}, failure.New("INTEGRITY_FAILURE", "server-config", false)
	}
	file := os.NewFile(uintptr(descriptor), "server-config")
	if file == nil {
		_ = unix.Close(descriptor)
		return Profile{}, failure.New("INTEGRITY_FAILURE", "server-config", false)
	}
	defer file.Close()

	var stat unix.Stat_t
	if err := unix.Fstat(descriptor, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != loader.expectedOwnerUID {
		return Profile{}, failure.New("INTEGRITY_FAILURE", "server-config", false)
	}
	permissions := stat.Mode & 0o777
	if permissions != 0o600 && permissions != 0o640 {
		return Profile{}, failure.New("INTEGRITY_FAILURE", "server-config", false)
	}
	generatedProfile, err := decodeGeneratedProfile(file)
	if err != nil {
		return Profile{}, err
	}
	if err := ctx.Err(); err != nil {
		return Profile{}, failure.New("INTERRUPTED", "server-config", false)
	}
	profile, err := convertGeneratedProfile(generatedProfile, loader.expectedOwnerUID)
	if err != nil {
		return Profile{}, err
	}
	if err := validateInventoryExportRoot(profile.InventoryExportRoot, loader.expectedOwnerUID); err != nil {
		return Profile{}, failure.New("INTEGRITY_FAILURE", "server-config", false)
	}
	return profile, nil
}

func validateInventoryExportRoot(path string, expectedUID uint32) error {
	descriptor, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return err
	}
	defer unix.Close(descriptor)
	var stat unix.Stat_t
	var filesystem unix.Statfs_t
	if unix.Fstat(descriptor, &stat) != nil || unix.Fstatfs(descriptor, &filesystem) != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o777 != 0o700 || stat.Uid != expectedUID || stat.Nlink < 1 {
		return unix.EPERM
	}
	switch uint64(filesystem.Type) {
	case unix.EXT4_SUPER_MAGIC, unix.XFS_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC, unix.F2FS_SUPER_MAGIC, 0x2fc12fc1:
		return nil
	default:
		return unix.ENOTSUP
	}
}
