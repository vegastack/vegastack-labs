//go:build linux

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/vegastack/vegastack-labs/internal/cijobrunner"
)

func runCIJobMode(ctx context.Context, args []string) (bool, int) {
	if len(args) == 0 || (args[0] != cijobrunner.PID1Mode && args[0] != cijobrunner.HookMode && args[0] != cijobrunner.WorkerMode) {
		return false, 0
	}
	if len(args) != 1 {
		return true, 1
	}
	ctx, cancel := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	var e error
	if args[0] == cijobrunner.PID1Mode {
		e = cijobrunner.RunEntrypoint(ctx, os.Stdin, os.Stdout)
	} else if args[0] == cijobrunner.WorkerMode {
		e = cijobrunner.RunWorker(ctx, os.Stdin, os.Stdout)
	} else {
		e = cijobrunner.RunFixedHook(ctx)
	}
	if e != nil {
		return true, 1
	}
	return true, 0
}
