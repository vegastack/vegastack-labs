//go:build linux

package qualification

import (
	"io"
	"os"
	"path/filepath"

	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"golang.org/x/sys/unix"
)

const fixtureControlFinalProfile = "/etc/vsk-labs/control/server-after-setup.json"

// Both fixed profiles belong to the isolated fixture. Invalid inputs leave
// the current profile untouched; later errors preserve artifacts and stop.
func replaceFixtureSignerProfile(initialPath, finalPath string, uid, gid uint32, pin string) (string, error) {
	if filepath.Dir(initialPath) != filepath.Dir(finalPath) || filepath.Base(initialPath) != "server.json" || filepath.Base(finalPath) != "server-after-setup.json" {
		return "", ErrUnavailable
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, filepath.Dir(initialPath), &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return "", ErrUnavailable
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || (st.Uid != 0 && st.Uid != uid) || st.Mode&0777 != 0700 {
		return "", ErrUnavailable
	}
	before, err := fixtureProfileAt(fd, "server.json", uid)
	if err != nil {
		return "", err
	}
	after, err := fixtureProfileAt(fd, "server-after-setup.json", uid)
	if err != nil || validateFixtureSignerProfiles(before, after, uid, pin) != nil {
		return "", ErrUnavailable
	}
	profile, err := serverconfig.DecodeProfile(after, uid)
	if err != nil || (profile.LocalBackup != nil && serverconfig.VerifyLocalBackup(profile.LocalBackup, uid) != nil) {
		return "", ErrUnavailable
	}
	const temporary = "server.signer-transition"
	tmp, err := unix.Openat(fd, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return "", ErrUnavailable
	}
	f := os.NewFile(uintptr(tmp), temporary)
	if err = f.Chown(int(uid), int(gid)); err == nil {
		_, err = f.Write(after)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return "", ErrUnavailable
	}
	current, err := fixtureProfileAt(fd, "server.json", uid)
	staged, se := fixtureProfileAt(fd, temporary, uid)
	if err != nil || se != nil || hostaction.BytesDigest(current) != pin || hostaction.BytesDigest(staged) != hostaction.BytesDigest(after) {
		return "", ErrUnavailable
	}
	if unix.Renameat(fd, temporary, fd, "server.json") != nil || unix.Fsync(fd) != nil {
		return "", ErrUnavailable
	}
	installed, err := fixtureProfileAt(fd, "server.json", uid)
	if err != nil || hostaction.BytesDigest(installed) != hostaction.BytesDigest(after) {
		return "", ErrUnavailable
	}
	return hostaction.BytesDigest(installed), nil
}

func fixtureProfileAt(directory int, name string, uid uint32) ([]byte, error) {
	fd, err := unix.Openat(directory, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != uid || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0777 != 0600 || st.Nlink != 1 || st.Size <= 0 || st.Size > 65536 {
		return nil, ErrUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || len(raw) > 65536 {
		return nil, ErrUnavailable
	}
	return raw, nil
}
