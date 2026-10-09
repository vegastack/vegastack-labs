//go:build linux

package main

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/debianaccess"
	"os"
)

func runAccessRollback(ctx context.Context, args []string) (bool, int) {
	if len(args) == 0 || args[0] != "access-rollback" {
		return false, 0
	}
	if len(args) != 1 || os.Getuid() != 0 || os.Geteuid() != 0 {
		return true, 1
	}
	if debianaccess.RestoreNative(ctx) != nil {
		return true, 1
	}
	return true, 0
}
