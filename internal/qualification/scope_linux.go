//go:build linux

package qualification

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// LoadServerScope reads a root-owned, service-group-readable fixture scope.
// Neither the service group nor any other unprivileged account may write it.
func LoadServerScope(ctx context.Context) (generated.QualificationScope, error) {
	var empty generated.QualificationScope
	if ctx.Err() != nil {
		return empty, ctx.Err()
	}
	account, err := user.Lookup("vsk-labs")
	if err != nil {
		return empty, ErrUnavailable
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uid == 0 {
		return empty, ErrUnavailable
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil || gid == 0 {
		return empty, ErrUnavailable
	}
	if os.Geteuid() != 0 && uint64(os.Geteuid()) != uid {
		return empty, ErrUnavailable
	}
	for _, path := range []string{"/etc", "/etc/vsk-labs", "/etc/vsk-labs/native"} {
		i, e := os.Lstat(path)
		if e != nil || !i.IsDir() || i.Mode().Perm()&0022 != 0 {
			return empty, ErrUnavailable
		}
		st, ok := i.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 {
			return empty, ErrUnavailable
		}
		if path == "/etc/vsk-labs/native" && (st.Gid != uint32(gid) || i.Mode().Perm() != 0750) {
			return empty, ErrUnavailable
		}
	}
	const path = "/etc/vsk-labs/native/scope.json"
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return empty, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return empty, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || st.Gid != uint32(gid) || st.Nlink != 1 || !info.Mode().IsRegular() || info.Mode().Perm() != 0640 || info.Size() > 65536 {
		return empty, ErrUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil || len(raw) > 65536 {
		return empty, ErrUnavailable
	}
	scope, err := DecodeScope(raw)
	if err != nil || scope.ControlServiceUID != int64(uid) || scope.ControlServiceGID != int64(gid) {
		return empty, ErrUnavailable
	}
	return scope, nil
}

// loadGuestScope is for the root-only disposable witness/step executable on
// non-controller guests, which do not need a control service account installed.
func loadGuestScope(ctx context.Context) (generated.QualificationScope, error) {
	var empty generated.QualificationScope
	if os.Geteuid() != 0 || ctx.Err() != nil {
		return empty, ErrUnavailable
	}
	const root = "/etc/vsk-labs/native"
	info, err := os.Lstat(root)
	if err != nil {
		return empty, err
	}
	if info.Mode().Perm() == 0750 {
		return LoadServerScope(ctx)
	}
	if ownedDirectory(root, 0) != nil {
		return empty, ErrUnavailable
	}
	raw, err := ownedFile(root+"/scope.json", 0, 65536)
	if err != nil {
		return empty, err
	}
	return DecodeScope(raw)
}
