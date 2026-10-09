//go:build !linux

package main

import "context"

func runAccessRollback(_ context.Context, args []string) (bool, int) {
	if len(args) > 0 && args[0] == "access-rollback" {
		return true, 1
	}
	return false, 0
}
