//go:build !windows

package clientprofile

import (
	"os"
	"syscall"
)

func trustedFile(_ string, info os.FileInfo) bool {
	metadata, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode().IsRegular() && info.Mode().Perm() == 0o600 && metadata.Nlink == 1 && metadata.Uid == uint32(os.Geteuid())
}

func trustedExecutable(_ string, info os.FileInfo) bool {
	metadata, ok := info.Sys().(*syscall.Stat_t)
	owner := uint32(os.Geteuid())
	return ok && info.Mode().IsRegular() && metadata.Nlink == 1 && (metadata.Uid == owner || metadata.Uid == 0) && info.Mode().Perm()&0o022 == 0 && info.Mode().Perm()&0o111 != 0
}
