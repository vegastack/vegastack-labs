//go:build linux

package main

import (
	"context"
	"crypto/rand"
	"github.com/vegastack/vegastack-labs/internal/debianaccess"
	"github.com/vegastack/vegastack-labs/internal/debianbaseline"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/linuxrole"
	"github.com/vegastack/vegastack-labs/internal/qualification"
	"github.com/vegastack/vegastack-labs/internal/server"
	"os"
	"strconv"
	"time"
)

func runHostActionOnce(ctx context.Context, args []string) (bool, int) {
	if len(args) == 1 && args[0] == qualification.NativeAPIMode {
		if qualification.RunNativeAPIOnce(ctx, os.Stdin, os.Stdout) != nil {
			return true, 1
		}
		return true, 0
	}
	if len(args) == 1 && args[0] == server.RecoveryReceiveMode {
		if server.RunRecoveryReceiveOnce(ctx, toolVersion, os.Stdout) != nil {
			return true, 1
		}
		return true, 0
	}
	if len(args) == 2 && args[0] == linuxrole.BoundaryProbeMode {
		pid, e := strconv.ParseInt(args[1], 10, 32)
		if e != nil || linuxrole.RunBoundaryProbe(pid, os.Stdout) != nil {
			return true, 1
		}
		return true, 0
	}
	if len(args) == 1 && args[0] == linuxrole.HandoffWorkerMode {
		if linuxrole.RunControlHandoff(ctx, toolVersion) != nil {
			return true, 1
		}
		return true, 0
	}
	if len(args) == 1 && args[0] == linuxrole.HandoffHealthMode {
		if linuxrole.WriteControlHealth(ctx, os.Stdout) != nil {
			return true, 1
		}
		return true, 0
	}
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
	if hostaction.RunOnce(ctx, os.Stdin, os.Stdout, policy, receipts, nativeHostDispatcher{access: debianaccess.NewDispatcher(debianaccess.NewNativeRuntime(toolVersion)), baseline: debianbaseline.NewDispatcher(debianbaseline.NewNativeRuntime(toolVersion)), role: linuxrole.NewDispatcher(linuxrole.NewNativeRuntime(toolVersion)), recovery: server.RecoveryReceiveDispatcher(toolVersion)}, time.Now, rand.Reader) != nil {
		return true, 1
	}
	return true, 0
}

type nativeHostDispatcher struct{ access, baseline, role, recovery hostaction.Dispatcher }

func (d nativeHostDispatcher) Lookup(id, version string) (hostaction.Handler, bool) {
	if h, ok := d.access.Lookup(id, version); ok {
		return h, true
	}
	if h, ok := d.baseline.Lookup(id, version); ok {
		return h, true
	}
	if d.recovery != nil {
		if h, ok := d.recovery.Lookup(id, version); ok {
			return h, true
		}
	}
	if d.role != nil {
		return d.role.Lookup(id, version)
	}
	return nil, false
}
