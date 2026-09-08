//go:build linux

package store

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

type linuxFilesystem struct{}

func storePlatformSupported() bool { return true }

func newFilesystemInspector() FilesystemInspector { return linuxFilesystem{} }

func (linuxFilesystem) InspectParent(ctx context.Context, databasePath string, expectedUID uint32) (FileIdentity, error) {
	if err := validateDatabasePath(ctx, databasePath); err != nil {
		return FileIdentity{}, err
	}
	parent := filepath.Dir(databasePath)
	info, err := os.Lstat(parent)
	if err != nil {
		return FileIdentity{}, filesystemError(err)
	}
	identity, err := fileIdentity(parent, info)
	if err != nil {
		return FileIdentity{}, filesystemError(err)
	}
	if !info.IsDir() {
		return FileIdentity{}, filesystemError(errors.New("parent is not a directory"))
	}
	if identity.UID != expectedUID {
		return FileIdentity{}, filesystemError(errors.New("parent owner differs"))
	}
	if info.Mode().Perm() != 0o700 {
		return FileIdentity{}, filesystemError(errors.New("parent mode is weak"))
	}
	if !identity.Local {
		return FileIdentity{}, filesystemError(errors.New("parent filesystem is not local"))
	}
	return identity, nil
}

func (linuxFilesystem) CreateDatabase(ctx context.Context, databasePath string, expectedUID uint32) (FileIdentity, error) {
	if _, err := (linuxFilesystem{}).InspectParent(ctx, databasePath, expectedUID); err != nil {
		return FileIdentity{}, err
	}
	if _, err := os.Lstat(databasePath); err == nil {
		return FileIdentity{}, classifyExistingDatabase(databasePath)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return FileIdentity{}, filesystemError(err)
	}
	file, err := os.OpenFile(databasePath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return FileIdentity{}, classifyExistingDatabase(databasePath)
		}
		return FileIdentity{}, filesystemError(err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return FileIdentity{}, filesystemError(err)
	}
	info, statErr := file.Stat()
	closeErr := file.Close()
	if statErr != nil {
		return FileIdentity{}, filesystemError(statErr)
	}
	if closeErr != nil {
		return FileIdentity{}, filesystemError(closeErr)
	}
	identity, err := fileIdentity(databasePath, info)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || identity.UID != expectedUID || identity.Links != 1 || !identity.Local {
		if err == nil {
			err = errors.New("database protection failed")
		}
		return FileIdentity{}, filesystemError(err)
	}
	if err := syncDirectory(filepath.Dir(databasePath)); err != nil {
		return FileIdentity{}, filesystemError(err)
	}
	return identity, nil
}

func classifyExistingDatabase(databasePath string) error {
	info, err := os.Lstat(databasePath)
	if err != nil {
		return filesystemError(err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return filesystemError(errors.New("database target is unsafe"))
	}
	return newStoreError("STATE_CONFLICT", "database", false, fs.ErrExist)
}

func (linuxFilesystem) InspectDatabase(ctx context.Context, databasePath string, expectedUID uint32) (FileIdentity, error) {
	if _, err := (linuxFilesystem{}).InspectParent(ctx, databasePath, expectedUID); err != nil {
		return FileIdentity{}, err
	}
	info, err := os.Lstat(databasePath)
	if err != nil {
		return FileIdentity{}, filesystemError(err)
	}
	identity, err := fileIdentity(databasePath, info)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || identity.UID != expectedUID || identity.Links != 1 || info.Size() == 0 || !identity.Local {
		if err == nil {
			err = errors.New("database protection failed")
		}
		return FileIdentity{}, filesystemError(err)
	}
	return identity, nil
}

func (linuxFilesystem) AcquireWriterLock(ctx context.Context, databasePath string, expectedUID uint32) (io.Closer, error) {
	if err := ctx.Err(); err != nil {
		return nil, newStoreError("INTERRUPTED", "database-lock", false, err)
	}
	lockPath := databasePath + ".lock"
	descriptor, err := unix.Open(lockPath, unix.O_CLOEXEC|unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, filesystemError(err)
	}
	file := os.NewFile(uintptr(descriptor), "database-writer-lock")
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, filesystemError(errors.New("lock descriptor unavailable"))
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, filesystemError(err)
	}
	identity, err := fileIdentity(lockPath, info)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || identity.UID != expectedUID || identity.Links != 1 || !identity.Local {
		_ = file.Close()
		if err == nil {
			err = errors.New("lock protection failed")
		}
		return nil, filesystemError(err)
	}
	if err := unix.Flock(descriptor, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, newStoreError("STATE_CONFLICT", "database-writer", true, err)
		}
		return nil, filesystemError(err)
	}
	return &writerLock{file: file}, nil
}

func (linuxFilesystem) SameFile(left, right FileIdentity) bool {
	return left.Device == right.Device && left.Inode == right.Inode && left.UID == right.UID && left.Mode.Perm() == right.Mode.Perm() && left.Links == right.Links && left.Local && right.Local
}

func (linuxFilesystem) SyncDatabase(ctx context.Context, databasePath string, expected FileIdentity) error {
	if err := ctx.Err(); err != nil {
		return newStoreError("INTERRUPTED", "database-sync", false, err)
	}
	file, err := os.OpenFile(databasePath, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return filesystemError(err)
	}
	info, statErr := file.Stat()
	if statErr == nil {
		var actual FileIdentity
		actual, statErr = fileIdentity(databasePath, info)
		if statErr == nil && !(linuxFilesystem{}).SameFile(expected, actual) {
			statErr = errors.New("database identity changed")
		}
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	if statErr != nil {
		return filesystemError(statErr)
	}
	if syncErr != nil {
		return filesystemError(syncErr)
	}
	if closeErr != nil {
		return filesystemError(closeErr)
	}
	if err := syncDirectory(filepath.Dir(databasePath)); err != nil {
		return filesystemError(err)
	}
	return nil
}

type writerLock struct {
	once sync.Once
	file *os.File
	err  error
}

func (lock *writerLock) Close() error {
	lock.once.Do(func() {
		if err := unix.Flock(int(lock.file.Fd()), unix.LOCK_UN); err != nil {
			lock.err = filesystemError(err)
		}
		if err := lock.file.Close(); err != nil && lock.err == nil {
			lock.err = filesystemError(err)
		}
	})
	return lock.err
}

func validateDatabasePath(ctx context.Context, databasePath string) error {
	if err := ctx.Err(); err != nil {
		return newStoreError("INTERRUPTED", "database-path", false, err)
	}
	if databasePath == "" || strings.ContainsRune(databasePath, 0) || !filepath.IsAbs(databasePath) || filepath.Clean(databasePath) != databasePath || filepath.Base(databasePath) == "." || filepath.Base(databasePath) == string(filepath.Separator) {
		return filesystemError(errors.New("database path is invalid"))
	}
	parent := filepath.Dir(databasePath)
	current := string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimPrefix(parent, string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			if err == nil {
				err = errors.New("database path component is unsafe")
			}
			return filesystemError(err)
		}
	}
	return nil
}

func fileIdentity(path string, info fs.FileInfo) (FileIdentity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return FileIdentity{}, errors.New("file identity unavailable")
	}
	local, err := localFilesystem(path)
	if err != nil {
		return FileIdentity{}, err
	}
	return FileIdentity{Device: uint64(stat.Dev), Inode: stat.Ino, Links: uint64(stat.Nlink), UID: stat.Uid, Mode: info.Mode(), Local: local}, nil
}

func localFilesystem(path string) (bool, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return false, err
	}
	switch uint64(stat.Type) {
	case 0x6969, 0x517b, 0xff534d42, 0x65735546, 0x5346414f:
		return false, nil
	default:
		return true, nil
	}
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

func filesystemError(cause error) error {
	if Code(cause) != "" {
		return cause
	}
	return newStoreError("INTEGRITY_FAILURE", "database-filesystem", false, cause)
}
