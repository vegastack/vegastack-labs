//go:build linux

package server

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/adapters/slack"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"golang.org/x/sys/unix"
)

func openLocalSetupDirectory(path string, uid uint32) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, setupFailure(generated.ErrorCodeInputInvalid)
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return nil, setupFailure(generated.ErrorCodePrerequisiteBlocked)
	}
	file := os.NewFile(uintptr(fd), "local-setup-directory")
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != uid || st.Mode&0077 != 0 {
		file.Close()
		return nil, setupFailure(generated.ErrorCodeIntegrityFailure)
	}
	return file, nil
}
func readLocalSetupProtected(ctx context.Context, path string, uid uint32, limit int64) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, setupFailure(generated.ErrorCodeInputInvalid)
	}
	parent, err := openLocalSetupDirectory(filepath.Dir(path), uid)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	fd, err := unix.Openat(int(parent.Fd()), filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, setupFailure(generated.ErrorCodePrerequisiteBlocked)
	}
	file := os.NewFile(uintptr(fd), "local-setup-input")
	defer file.Close()
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 || before.Uid != uid || before.Mode&0777 != 0600 || before.Size <= 0 || before.Size > limit {
		return nil, setupFailure(generated.ErrorCodeIntegrityFailure)
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) != before.Size || ctx.Err() != nil || unix.Fstat(fd, &after) != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mode != after.Mode || before.Uid != after.Uid || before.Nlink != after.Nlink || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return nil, setupFailure(generated.ErrorCodeIntegrityFailure)
	}
	return raw, nil
}
func localSetupHostIdentity(ctx context.Context) (string, error) {
	if ctx == nil || ctx.Err() != nil {
		return "", setupFailure(generated.ErrorCodeInterrupted)
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, "/etc/machine-id", &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return "", setupFailure(generated.ErrorCodePrerequisiteBlocked)
	}
	file := os.NewFile(uintptr(fd), "local-host-identity")
	defer file.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0022 != 0 {
		return "", setupFailure(generated.ErrorCodeIntegrityFailure)
	}
	raw, err := io.ReadAll(io.LimitReader(file, 129))
	if err != nil || len(raw) > 128 {
		return "", setupFailure(generated.ErrorCodeIntegrityFailure)
	}
	value := strings.TrimSpace(string(raw))
	if len(value) != 32 || strings.Trim(value, "0123456789abcdef") == value || value == strings.Repeat("0", 32) {
		return "", setupFailure(generated.ErrorCodeIntegrityFailure)
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return "", setupFailure(generated.ErrorCodeIntegrityFailure)
		}
	}
	return setupSHA256([]byte(value)), nil
}
func openLocalSetupExecutable() (io.ReadCloser, error) { return os.Open("/proc/self/exe") }

func localSetupAbsent(path string, uid uint32) error {
	parent, err := openLocalSetupDirectory(filepath.Dir(path), uid)
	if err != nil {
		return err
	}
	defer parent.Close()
	for _, suffix := range []string{"", "-wal", "-shm", "-journal", ".lock"} {
		var st unix.Stat_t
		err = unix.Fstatat(int(parent.Fd()), filepath.Base(path)+suffix, &st, unix.AT_SYMLINK_NOFOLLOW)
		if err != unix.ENOENT {
			return setupFailure(generated.ErrorCodeStateConflict)
		}
	}
	return nil
}
func writeLocalSetupReceipt(ctx context.Context, path string, uid uint32, raw []byte) error {
	if ctx.Err() != nil {
		return setupFailure(generated.ErrorCodeInterrupted)
	}
	parent, err := openLocalSetupDirectory(filepath.Dir(path), uid)
	if err != nil {
		return err
	}
	defer parent.Close()
	fd, err := unix.Openat(int(parent.Fd()), filepath.Base(path), unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return setupFailure(generated.ErrorCodeStateConflict)
	}
	file := os.NewFile(uintptr(fd), "local-setup-approval-receipt")
	_, err = file.Write(raw)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = parent.Sync()
	}
	if err != nil {
		return setupFailure(generated.ErrorCodeIntegrityFailure)
	}
	return nil
}
func newLocalSetupCredentialResolver(uid uint32) (slack.CredentialResolver, io.Closer, error) {
	directory, err := openLocalSetupDirectory(os.Getenv("CREDENTIALS_DIRECTORY"), uid)
	if err != nil {
		return nil, nil, err
	}
	return &systemdCredentialResolver{directory: directory, ownerUID: uid}, directory, nil
}
