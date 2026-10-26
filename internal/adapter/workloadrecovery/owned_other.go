//go:build !linux && !darwin

package workloadrecovery

import "os"

// The native encrypted repository path is unsupported on these platforms.
func ownedDirectory(os.FileInfo) bool { return false }
