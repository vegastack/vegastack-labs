//go:build linux || darwin

package hostaction

import (
	"os"
	"path/filepath"
	"syscall"
)

func rendererRootOwner(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 0
}
func protectedRendererPath(path string) bool {
	// Debian interpreter is a root-owned symlink to its versioned binary; resolve
	// it, then validate every resolved ancestor and the original symlink owner.
	original, err := os.Lstat(path)
	if err != nil || !rendererRootOwner(original) {
		return false
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}
	for p := resolved; ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil || !rendererRootOwner(info) || info.Mode().Perm()&0022 != 0 || info.Mode()&os.ModeSymlink != 0 {
			return false
		}
		if p == resolved && !info.Mode().IsRegular() && !info.IsDir() {
			return false
		}
		if p == "/" {
			break
		}
	}
	return true
}
