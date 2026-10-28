//go:build linux

package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"github.com/vegastack/vegastack-labs/internal/linuxrole"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"golang.org/x/sys/unix"
	"io"
	"os"
)

// The finite operator client decodes the protected server profile without
// opening server-only inventory/export directories after custody transfer.
// The persistent server still uses the ordinary full loader.
func loadControllerSetupClientProfile(ctx context.Context, path string, owner, adminGroup uint32) (serverconfig.Profile, error) {
	if ctx.Err() != nil {
		return serverconfig.Profile{}, ctx.Err()
	}
	fd, e := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if e != nil {
		return serverconfig.Profile{}, actionFailure()
	}
	f := os.NewFile(uintptr(fd), "controller-setup-profile")
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != owner || st.Size <= 0 || st.Size > 1<<20 || (st.Mode&0777 != 0600 && (st.Mode&0777 != 0640 || st.Gid != adminGroup)) {
		return serverconfig.Profile{}, actionFailure()
	}
	b, e := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if e != nil || len(b) > 1<<20 {
		return serverconfig.Profile{}, actionFailure()
	}
	return serverconfig.DecodeProfile(b, owner)
}

// The preserved image is an actual fixed server-owned snapshot artifact. The
// digest is re-observed for every claim/receipt; a policy string is not proof.
func verifyControllerRecoveryImage(ctx context.Context, in linuxrole.ControllerInstallInput) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	fd, e := unix.Openat2(unix.AT_FDCWD, linuxrole.ControllerRecoveryImage, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if e != nil {
		return actionFailure()
	}
	f := os.NewFile(uintptr(fd), "controller-recovery-image")
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0777 != 0600 || st.Nlink != 1 || st.Size <= 0 || st.Size > 4<<30 || (st.Uid != uint32(in.AdministratorUID) && st.Uid != uint32(in.ServiceUID)) {
		return actionFailure()
	}
	h := sha256.New()
	if _, e = io.Copy(h, io.LimitReader(f, 4<<30+1)); e != nil || "sha256:"+hex.EncodeToString(h.Sum(nil)) != in.RecoveryImageDigest {
		return actionFailure()
	}
	return nil
}
