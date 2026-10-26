//go:build linux || darwin

package workloadrecovery

import (
	"os"
	"syscall"
)

func ownedDirectory(st os.FileInfo) bool {
	s, ok := st.Sys().(*syscall.Stat_t)
	return ok && s.Uid == uint32(os.Geteuid())
}
