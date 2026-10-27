//go:build !linux

package main

import "context"

func runCIJobMode(_ context.Context, args []string) (bool, int) {
	if len(args) > 0 && (args[0] == "ci-job-init" || args[0] == "ci-job-hook" || args[0] == "ci-job-worker") {
		return true, 1
	}
	return false, 0
}
