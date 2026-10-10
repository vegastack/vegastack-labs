//go:build linux

package linuxrole

import (
	"bytes"
	"context"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"strconv"
	"time"
)

// InspectNativeRecoveryDestination observes an installed but inactive control
// role. It neither starts its service nor creates a database or owned path.
func InspectNativeRecoveryDestination(ctx context.Context, b generated.HostActionBundle, in generated.LinuxRoleInput, uid, gid int64) error {
	if ValidateInput(in) != nil || in.RoleID != "control" || len(in.Accounts) != 1 || in.Accounts[0].Selector != "control" || in.Accounts[0].UID != uid || in.Accounts[0].GID != gid {
		return errNative
	}
	n := NewNativeRuntime(in.ProfileLock.ExecutableVersion).(*nativeRuntime)
	if e := n.Inspect(ctx, b, in); e != nil {
		return e
	}
	for _, a := range in.Accounts {
		if _, e := n.account(ctx, a, false); e != nil {
			return e
		}
	}
	for _, d := range in.Directories {
		if _, e := n.directory(in, d, false); e != nil {
			return e
		}
	}
	if e := n.activeControlFiles(in); e != nil {
		return e
	}
	if e := n.unitOverrides(UnitName(in.RoleID)); e != nil {
		return e
	}
	for p, want := range DesiredFiles(in) {
		got, e := readProtected(n.root, p, 65536)
		if e != nil || !bytes.Equal(got, want) {
			return errNative
		}
	}
	raw, e := n.run(ctx, "/usr/bin/systemctl", resourceArgs(in))
	if e != nil {
		return e
	}
	p := parseProperties(raw)
	cpu := fmt.Sprintf("%dms", in.Resources.CPUQuotaPercent*10)
	if p["ActiveState"] != "inactive" || p["MainPID"] != "0" || p["User"] != strconv.FormatInt(uid, 10) || p["Group"] != strconv.FormatInt(gid, 10) || p["FragmentPath"] != "/etc/systemd/system/vsk-labs.service" || p["DropInPaths"] != "" || p["UnitFileState"] != "enabled" || p["MemoryMax"] != strconv.FormatInt(in.Resources.MemoryMaxBytes, 10) || p["TasksMax"] != strconv.FormatInt(in.Resources.TasksMax, 10) || (p["CPUQuotaPerSecUSec"] != cpu && p["CPUQuotaPerSecUSec"] != time.Duration(in.Resources.CPUQuotaPercent*10000000).String()) {
		return errNative
	}
	if e = n.capacity(in); e != nil {
		return e
	}
	return n.freeSpace(in)
}
