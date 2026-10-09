//go:build !linux && !darwin

package hostaction

import "os"

func rendererRootOwner(os.FileInfo) bool { return false }
func protectedRendererPath(string) bool  { return false }
