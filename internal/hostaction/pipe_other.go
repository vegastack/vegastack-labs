//go:build !linux && !darwin

package hostaction

import "os"

// The privileged helper is unavailable on these platforms.
func interruptiblePipe(*os.File) (*os.File, func(), error) { return nil, nil, blocked() }
