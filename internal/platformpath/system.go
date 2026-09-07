package platformpath

import (
	"os"
	"path/filepath"
	"runtime"
)

// System creates a resolver backed by the current operating system.
func System() (*Resolver, error) {
	return New(Sources{
		GOOS:          runtime.GOOS,
		LookupEnv:     os.LookupEnv,
		UserHomeDir:   os.UserHomeDir,
		UserConfigDir: os.UserConfigDir,
		UserCacheDir:  os.UserCacheDir,
		Ops: PathOps{
			Join:  filepath.Join,
			Clean: filepath.Clean,
			IsAbs: filepath.IsAbs,
		},
	})
}
