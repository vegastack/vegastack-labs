//go:build !windows

package clientprofile

import (
	"os"
	"syscall"
)

func trustedFile(info os.FileInfo) bool {
	metadata, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode().IsRegular() && info.Mode().Perm() == 0o600 && metadata.Nlink == 1 && metadata.Uid == uint32(os.Geteuid())
}
