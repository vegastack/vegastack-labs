//go:build linux

package identity

import (
	"io"
	"os"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"golang.org/x/sys/unix"
)

func openProtectedCloudflareAccessProfile(profilePath string) (io.ReadCloser, error) {
	descriptor, err := unix.Openat2(unix.AT_FDCWD, profilePath, &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW),
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, failure.New("INTEGRITY_FAILURE", "cloudflare-access-config", false)
	}
	file := os.NewFile(uintptr(descriptor), "cloudflare-access-config")
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, failure.New("INTEGRITY_FAILURE", "cloudflare-access-config", false)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(descriptor, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) || (stat.Mode&0o777 != 0o600 && stat.Mode&0o777 != 0o640) {
		_ = file.Close()
		return nil, failure.New("INTEGRITY_FAILURE", "cloudflare-access-config", false)
	}
	return file, nil
}
