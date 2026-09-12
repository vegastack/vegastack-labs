//go:build linux

package server

import (
	"io"
	"os"

	"golang.org/x/sys/unix"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

func openProtectedSlackAcknowledgementProfile(path string, ownerUID uint32) (io.ReadCloser, error) {
	descriptor, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW),
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, failure.New(generated.ErrorCodeIntegrityFailure, "acknowledgement-adapter-config", false)
	}
	file := os.NewFile(uintptr(descriptor), "acknowledgement-adapter-config")
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, failure.New(generated.ErrorCodeIntegrityFailure, "acknowledgement-adapter-config", false)
	}
	var stat unix.Stat_t
	permissions := uint32(0)
	if unix.Fstat(descriptor, &stat) == nil {
		permissions = stat.Mode & 0o777
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != ownerUID || (permissions != 0o600 && permissions != 0o640) {
		_ = file.Close()
		return nil, failure.New(generated.ErrorCodeIntegrityFailure, "acknowledgement-adapter-config", false)
	}
	return file, nil
}
