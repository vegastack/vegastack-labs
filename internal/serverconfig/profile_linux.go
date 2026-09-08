//go:build linux

package serverconfig

import (
	"context"
	"os"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"golang.org/x/sys/unix"
)

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
	return convertGeneratedProfile(generatedProfile, loader.expectedOwnerUID)
}
