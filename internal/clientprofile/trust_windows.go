//go:build windows

package clientprofile

import "os"

// Windows file trust is bounded by the non-reparse, stable-handle checks in
// profile.go. POSIX ownership/mode semantics do not exist on Windows.
func trustedFile(info os.FileInfo) bool {
	return info.Mode().IsRegular()
}
