package main

import (
	"crypto/sha256"
	"fmt"
)

// Fixed metadata-only collector: exact file/bytes, never a package/suffix scope.
func reviewedControllerPrerequisiteUnixFile(relative string, content []byte) bool {
	return relative == "internal/controllerprerequisites/collect_posix.go" && fmt.Sprintf("%x", sha256.Sum256(content)) == "8d55d4d743971ebd42dd4c8d5ee64d44d2d799b6c21d6a5de2238d10769403e6"
}
