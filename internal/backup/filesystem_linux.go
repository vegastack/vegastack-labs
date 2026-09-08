//go:build linux

package backup

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

type linuxArtifactLayout struct {
	root        string
	expectedUID uint32
	entropy     io.Reader
}

func newArtifactLayout(config Config) (artifactLayout, error) {
	if config.Entropy == nil {
		config.Entropy = rand.Reader
	}
	layout := &linuxArtifactLayout{root: config.Root, expectedUID: config.ExpectedUID, entropy: config.Entropy}
	if err := layout.validateRoot(context.Background()); err != nil {
		return nil, err
	}
	return layout, nil
}

func (layout *linuxArtifactLayout) BeginGeneration(ctx context.Context, snapshotID string) (stagedGeneration, error) {
	if err := layout.validateRoot(ctx); err != nil || !validSnapshotID(snapshotID) {
		return stagedGeneration{}, classified(err, integrityError())
	}
	directory := filepath.Join(layout.root, ".staging-"+snapshotID)
	if err := mkdirExclusive(directory); err != nil {
		return stagedGeneration{}, integrityError()
	}
	if err := layout.validateOwnedDirectory(directory); err != nil {
		_ = os.Remove(directory)
		return stagedGeneration{}, err
	}
	return stagedGeneration{
		id:       snapshotID,
		dir:      directory,
		database: filepath.Join(directory, databaseFileName),
		manifest: filepath.Join(directory, manifestFileName),
	}, nil
}

func (layout *linuxArtifactLayout) SealDatabase(ctx context.Context, staged stagedGeneration) (fileIdentity, int64, [32]byte, error) {
	if err := layout.validateStage(ctx, staged); err != nil {
		return fileIdentity{}, 0, [32]byte{}, err
	}
	identity, size, digest, err := inspectAndDigest(staged.database, layout.expectedUID, true)
	if err != nil {
		return fileIdentity{}, 0, [32]byte{}, integrityError()
	}
	return identity, size, digest, nil
}

func (layout *linuxArtifactLayout) WriteManifest(ctx context.Context, staged stagedGeneration, body []byte) error {
	if err := layout.validateStage(ctx, staged); err != nil {
		return err
	}
	if _, err := parseManifest(body); err != nil {
		return integrityError()
	}
	file, err := os.OpenFile(staged.manifest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return integrityError()
	}
	written, writeErr := file.Write(body)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || written != len(body) || syncErr != nil || closeErr != nil {
		return integrityError()
	}
	if _, _, _, err := inspectAndDigest(staged.manifest, layout.expectedUID, false); err != nil {
		return integrityError()
	}
	return nil
}

func (layout *linuxArtifactLayout) Publish(ctx context.Context, staged stagedGeneration) (publishedGeneration, error) {
	if err := layout.validateStage(ctx, staged); err != nil {
		return publishedGeneration{}, err
	}
	identity, size, digest, err := inspectAndDigest(staged.database, layout.expectedUID, true)
	if err != nil || staged.databaseIdentity == (fileIdentity{}) || identity != staged.databaseIdentity {
		return publishedGeneration{}, integrityError()
	}
	body, err := readProtectedFile(staged.manifest, layout.expectedUID, 64*1024)
	if err != nil {
		return publishedGeneration{}, integrityError()
	}
	manifest, err := parseManifest(body)
	if err != nil || manifest.SnapshotID != staged.id || manifest.DatabaseSize != size || manifest.DatabaseSHA256 != fmt.Sprintf("%x", digest) {
		return publishedGeneration{}, integrityError()
	}
	if err := syncDirectory(staged.dir); err != nil {
		return publishedGeneration{}, integrityError()
	}
	finalDirectory := filepath.Join(layout.root, staged.id)
	if err := unix.Renameat2(unix.AT_FDCWD, staged.dir, unix.AT_FDCWD, finalDirectory, unix.RENAME_NOREPLACE); err != nil {
		return publishedGeneration{}, integrityError()
	}
	published := publishedGeneration{
		id:               staged.id,
		dir:              finalDirectory,
		database:         filepath.Join(finalDirectory, databaseFileName),
		manifest:         filepath.Join(finalDirectory, manifestFileName),
		databaseIdentity: staged.databaseIdentity,
	}
	if err := syncDirectory(layout.root); err != nil {
		return publishedGeneration{}, integrityError()
	}
	return published, nil
}

func (layout *linuxArtifactLayout) OpenPublished(ctx context.Context, snapshotID string) (publishedGeneration, []byte, error) {
	if err := layout.validateRoot(ctx); err != nil || !validSnapshotID(snapshotID) {
		return publishedGeneration{}, nil, classified(err, integrityError())
	}
	directory := filepath.Join(layout.root, snapshotID)
	if err := layout.validateOwnedDirectory(directory); err != nil {
		return publishedGeneration{}, nil, integrityError()
	}
	database := filepath.Join(directory, databaseFileName)
	manifestPath := filepath.Join(directory, manifestFileName)
	identity, size, digest, err := inspectAndDigest(database, layout.expectedUID, false)
	if err != nil {
		return publishedGeneration{}, nil, integrityError()
	}
	body, err := readProtectedFile(manifestPath, layout.expectedUID, 64*1024)
	if err != nil {
		return publishedGeneration{}, nil, integrityError()
	}
	manifest, err := parseManifest(body)
	if err != nil || manifest.SnapshotID != snapshotID || manifest.DatabaseSize != size || manifest.DatabaseSHA256 != fmt.Sprintf("%x", digest) {
		return publishedGeneration{}, nil, integrityError()
	}
	return publishedGeneration{id: snapshotID, dir: directory, database: database, manifest: manifestPath, databaseIdentity: identity}, body, nil
}

func (layout *linuxArtifactLayout) BeginRestore(ctx context.Context, snapshotID string) (restoreTarget, error) {
	if err := layout.validateRoot(ctx); err != nil || !validSnapshotID(snapshotID) {
		return restoreTarget{}, classified(err, integrityError())
	}
	suffix, err := randomID(layout.entropy)
	if err != nil {
		return restoreTarget{}, integrityError()
	}
	directory := filepath.Join(layout.root, ".restore-"+snapshotID+"-"+suffix)
	if err := mkdirExclusive(directory); err != nil {
		return restoreTarget{}, integrityError()
	}
	if err := layout.validateOwnedDirectory(directory); err != nil {
		_ = os.Remove(directory)
		return restoreTarget{}, err
	}
	return restoreTarget{dir: directory, database: filepath.Join(directory, databaseFileName)}, nil
}

func (layout *linuxArtifactLayout) SealRestore(ctx context.Context, target restoreTarget) (fileIdentity, int64, error) {
	if err := layout.validateRestore(ctx, target); err != nil {
		return fileIdentity{}, 0, err
	}
	identity, size, _, err := inspectAndDigest(target.database, layout.expectedUID, true)
	if err != nil {
		return fileIdentity{}, 0, integrityError()
	}
	return identity, size, nil
}

func (layout *linuxArtifactLayout) RemoveRestore(ctx context.Context, target restoreTarget) error {
	if err := layout.validateRestorePath(ctx, target); err != nil {
		return err
	}
	if err := os.Remove(target.database); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return integrityError()
	}
	if err := os.Remove(target.dir); err != nil {
		return integrityError()
	}
	return nil
}

func (layout *linuxArtifactLayout) validateStage(ctx context.Context, staged stagedGeneration) error {
	if err := layout.validateRoot(ctx); err != nil || !validSnapshotID(staged.id) {
		return classified(err, integrityError())
	}
	expectedDirectory := filepath.Join(layout.root, ".staging-"+staged.id)
	if staged.dir != expectedDirectory || staged.database != filepath.Join(expectedDirectory, databaseFileName) || staged.manifest != filepath.Join(expectedDirectory, manifestFileName) {
		return integrityError()
	}
	return layout.validateOwnedDirectory(expectedDirectory)
}

func (layout *linuxArtifactLayout) validateRestore(ctx context.Context, target restoreTarget) error {
	if err := layout.validateRestorePath(ctx, target); err != nil {
		return err
	}
	return layout.validateOwnedDirectory(target.dir)
}

func (layout *linuxArtifactLayout) validateRestorePath(ctx context.Context, target restoreTarget) error {
	if err := layout.validateRoot(ctx); err != nil {
		return err
	}
	base := filepath.Base(target.dir)
	if !strings.HasPrefix(base, ".restore-") || filepath.Dir(target.dir) != layout.root || target.database != filepath.Join(target.dir, databaseFileName) {
		return integrityError()
	}
	return nil
}

func (layout *linuxArtifactLayout) validateRoot(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return interruptedError()
	}
	if layout.root == "" || strings.ContainsRune(layout.root, 0) || !filepath.IsAbs(layout.root) || filepath.Clean(layout.root) != layout.root || layout.root == string(filepath.Separator) {
		return integrityError()
	}
	current := string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimPrefix(layout.root, string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return integrityError()
		}
	}
	return layout.validateOwnedDirectory(layout.root)
}

func (layout *linuxArtifactLayout) validateOwnedDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return integrityError()
	}
	identity, err := identify(path, info)
	if err != nil || identity.uid != layout.expectedUID || identity.links < 1 || !isLocal(path) {
		return integrityError()
	}
	return nil
}

func inspectAndDigest(path string, expectedUID uint32, sync bool) (fileIdentity, int64, [32]byte, error) {
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fileIdentity{}, 0, [32]byte{}, err
	}
	file := os.NewFile(uintptr(descriptor), "protected-artifact")
	if file == nil {
		_ = unix.Close(descriptor)
		return fileIdentity{}, 0, [32]byte{}, errors.New("descriptor unavailable")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() <= 0 {
		return fileIdentity{}, 0, [32]byte{}, errors.New("unsafe artifact")
	}
	identity, err := identify(path, info)
	if err != nil || identity.uid != expectedUID || identity.links != 1 || !isLocalDescriptor(descriptor) {
		return fileIdentity{}, 0, [32]byte{}, errors.New("unsafe artifact identity")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return fileIdentity{}, 0, [32]byte{}, err
	}
	if sync {
		if err := file.Sync(); err != nil {
			return fileIdentity{}, 0, [32]byte{}, err
		}
	}
	infoAfter, err := file.Stat()
	if err != nil || infoAfter.Size() != info.Size() {
		return fileIdentity{}, 0, [32]byte{}, errors.New("artifact changed while reading")
	}
	identityAfter, err := identify(path, infoAfter)
	if err != nil || identityAfter != identity {
		return fileIdentity{}, 0, [32]byte{}, errors.New("artifact identity changed")
	}
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	return identity, info.Size(), digest, nil
}

func readProtectedFile(path string, expectedUID uint32, limit int64) ([]byte, error) {
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), "protected-manifest")
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, errors.New("descriptor unavailable")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > limit {
		return nil, errors.New("unsafe manifest")
	}
	identity, err := identify(path, info)
	if err != nil || identity.uid != expectedUID || identity.links != 1 || !isLocalDescriptor(descriptor) {
		return nil, errors.New("unsafe manifest identity")
	}
	body, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(body)) != info.Size() {
		return nil, errors.New("manifest changed while reading")
	}
	infoAfter, err := file.Stat()
	if err != nil {
		return nil, err
	}
	identityAfter, err := identify(path, infoAfter)
	if err != nil || identityAfter != identity || infoAfter.Size() != info.Size() {
		return nil, errors.New("manifest identity changed")
	}
	return body, nil
}

func identify(path string, info fs.FileInfo) (fileIdentity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileIdentity{}, errors.New("identity unavailable")
	}
	return fileIdentity{device: uint64(stat.Dev), inode: stat.Ino, links: uint64(stat.Nlink), uid: stat.Uid, mode: uint32(info.Mode().Perm())}, nil
}

func isLocal(path string) bool {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return false
	}
	switch uint64(stat.Type) {
	case unix.EXT4_SUPER_MAGIC, unix.XFS_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC, unix.F2FS_SUPER_MAGIC, 0x2fc12fc1:
		return true
	default:
		return false
	}
}

func isLocalDescriptor(descriptor int) bool {
	var stat unix.Statfs_t
	if err := unix.Fstatfs(descriptor, &stat); err != nil {
		return false
	}
	return isLocalFilesystemType(uint64(stat.Type))
}

func isLocalFilesystemType(filesystemType uint64) bool {
	switch filesystemType {
	case unix.EXT4_SUPER_MAGIC, unix.XFS_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC, unix.F2FS_SUPER_MAGIC, 0x2fc12fc1:
		return true
	default:
		return false
	}
}

func mkdirExclusive(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}
