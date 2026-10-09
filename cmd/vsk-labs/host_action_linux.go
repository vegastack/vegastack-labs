//go:build linux

package main

import (
	"context"
	"crypto/rand"
	"github.com/vegastack/vegastack-labs/internal/debianaccess"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"os"
	"strconv"
	"time"
)

func runHostActionOnce(ctx context.Context, args []string) (bool, int) {
	if len(args) == 0 || args[0] != "host-action-once" {
		return false, 0
	}
	if len(args) != 1 || os.Getuid() != 0 || os.Geteuid() != 0 {
		return true, 1
	}
	policy, err := hostaction.LoadPolicy("/etc/vsk-labs/host-action.json")
	if err != nil {
		return true, 1
	}
	caller, err := strconv.ParseUint(os.Getenv("SUDO_UID"), 10, 32)
	if err != nil || caller == 0 || uint32(caller) != policy.CallerUID {
		return true, 1
	}
	receipts, err := hostaction.OpenReceipts(policy.ReceiptDirectory, 0)
	if err != nil {
		return true, 1
	}
	defer receipts.Close()
	if hostaction.RunOnce(ctx, os.Stdin, os.Stdout, policy, receipts, debianaccess.NewDispatcher(debianaccess.NewNativeRuntime(toolVersion)), time.Now, rand.Reader) != nil {
		return true, 1
	}
	return true, 0
}
