//go:build !windows

package networkconnect

import (
	"context"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
)

func ReadPrivateKey(ctx context.Context, path string) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, unavailable()
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, 0) {
		return nil, invalid()
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return nil, invalid()
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, invalid()
	}
	file := os.NewFile(uintptr(fd), "network-private-key")
	defer file.Close()
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Mode&0077 != 0 || before.Uid != uint32(os.Geteuid()) || before.Nlink != 1 || before.Size < 1 || before.Size > 32768 {
		return nil, invalid()
	}
	raw := make([]byte, before.Size)
	n, err := file.ReadAt(raw, 0)
	if err != nil || n != len(raw) || ctx.Err() != nil || unix.Fstat(fd, &after) != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim || before.Mode != after.Mode || before.Uid != after.Uid || before.Nlink != after.Nlink {
		clear(raw)
		return nil, invalid()
	}
	// Reopen without following links to reject a replacement of the path.
	current, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		clear(raw)
		return nil, invalid()
	}
	defer unix.Close(current)
	var now unix.Stat_t
	if unix.Fstat(current, &now) != nil || now.Dev != after.Dev || now.Ino != after.Ino || now.Mode != after.Mode || now.Uid != after.Uid || now.Nlink != after.Nlink {
		clear(raw)
		return nil, invalid()
	}
	return raw, nil
}
