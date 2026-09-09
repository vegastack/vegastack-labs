//go:build !windows

package clientfile

import (
	"context"
	"os"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"golang.org/x/sys/unix"
)

func readPlatform(ctx context.Context, path string, maximum int64) ([]byte, error) {
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, readError(generated.ErrorCodeInputInvalid)
	}
	file := os.NewFile(uintptr(descriptor), "inventory-file")
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, readError(generated.ErrorCodeIntegrityFailure)
	}
	defer file.Close()
	var before, after unix.Stat_t
	if unix.Fstat(descriptor, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 || before.Size < 1 || before.Size > maximum {
		return nil, readError(generated.ErrorCodeInputInvalid)
	}
	content, err := readBounded(ctx, file, maximum)
	if err != nil {
		return nil, err
	}
	if unix.Fstat(descriptor, &after) != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Nlink != after.Nlink || int64(len(content)) != after.Size {
		return nil, readError(generated.ErrorCodeIntegrityFailure)
	}
	currentDescriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, readError(generated.ErrorCodeIntegrityFailure)
	}
	defer unix.Close(currentDescriptor)
	var current unix.Stat_t
	if unix.Fstat(currentDescriptor, &current) != nil || current.Mode&unix.S_IFMT != unix.S_IFREG || current.Dev != after.Dev || current.Ino != after.Ino || current.Size != after.Size || current.Nlink != after.Nlink {
		return nil, readError(generated.ErrorCodeIntegrityFailure)
	}
	return content, nil
}
