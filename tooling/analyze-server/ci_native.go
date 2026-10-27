package main

import (
	"crypto/sha256"
	"fmt"
)

// #302/#303 confine native PTY/process and owned-cgroup operations to these
// exact Linux source files, exercised by the isolated native fixtures. This
// source binding grants no package-wide syscall scope or runtime authority.
func acceptedCINativeUnixFile(relative string, content []byte) bool {
	var expected string
	switch relative {
	case "internal/runnerbootstrap/config_linux.go":
		expected = "37c308922c9df1e6a08b0c19145c26bdde7ca5fa4d63194657a42c4691d3b765"
	case "internal/cijobguard/cgroup_linux.go":
		expected = "4e27550b6199855131e45273da6c48b3ef6b1fa6324deb3bbfac35fa1d72c386"
	default:
		return false
	}
	return fmt.Sprintf("%x", sha256.Sum256(content)) == expected
}
