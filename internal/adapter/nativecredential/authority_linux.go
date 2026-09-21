//go:build linux

package nativecredential

import (
	"context"
	"io"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type RestartReceipt struct {
	UnitName              string `json:"unit_name"`
	BootID                string `json:"boot_id"`
	RequestMonotonicNanos int64  `json:"request_monotonic_nanos"`
	FinishMonotonicNanos  int64  `json:"finish_monotonic_nanos"`
	Status                string `json:"status"`
}

type NativeAuthority interface {
	Restart(context.Context, string) (RestartReceipt, error)
	Probe(context.Context, AccessProbeRequest) (AccessProbeResult, error)
}

type LocalNativeAuthority struct{ enrolled []string }

func NewNativeAuthority(units []string) (*LocalNativeAuthority, error) {
	if len(units) == 0 || len(units) > 64 {
		return nil, errProbeBlocked
	}
	previous := ""
	for _, unit := range units {
		if !unitNamePattern.MatchString(unit) || strings.Contains(unit, "@.service") || strings.Contains(unit, "..") || unit <= previous {
			return nil, errProbeBlocked
		}
		previous = unit
	}
	return &LocalNativeAuthority{enrolled: append([]string(nil), units...)}, nil
}

func (a *LocalNativeAuthority) qualified(unit string) bool {
	if a == nil {
		return false
	}
	policy, err := readProbePolicy(probePolicyPath)
	if err != nil || !reflect.DeepEqual(policy.Units, a.enrolled) {
		return false
	}
	machine,err:=os.ReadFile("/etc/machine-id")
	if err!=nil || strings.TrimSpace(string(machine))!=policy.MachineID { return false }
	for _, allowed := range a.enrolled {
		if unit == allowed {
			return true
		}
	}
	return false
}

func (a *LocalNativeAuthority) Restart(ctx context.Context, unit string) (RestartReceipt, error) {
	if ctx == nil || ctx.Err() != nil || !a.qualified(unit) {
		return RestartReceipt{}, errProbeBlocked
	}
	bootBefore, err := currentBootID()
	if err != nil {
		return RestartReceipt{}, errProbeBlocked
	}
	start, err := monotonicNanos()
	if err != nil {
		return RestartReceipt{}, errProbeBlocked
	}
	bounded, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	systemctlFD,err:=openTrustedExecutable("/usr/bin/systemctl")
	if err!=nil { return RestartReceipt{},errProbeBlocked }
	defer systemctlFD.Close()
	cmd := exec.CommandContext(bounded, "/usr/bin/systemctl", "--system", "--no-ask-password", "restart", unit)
	cmd.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin"}
	cmd.Stdin = strings.NewReader("")
	cmd.Stdout = rejectCommandOutput{}
	cmd.Stderr = rejectCommandOutput{}
	if cmd.Run() != nil || bounded.Err() != nil {
		return RestartReceipt{}, errProbeBlocked
	}
	finish, err := monotonicNanos()
	if err != nil || finish < start {
		return RestartReceipt{}, errProbeBlocked
	}
	bootAfter, err := currentBootID()
	if err != nil || bootAfter != bootBefore || !a.qualified(unit) {
		return RestartReceipt{}, errProbeBlocked
	}
	return RestartReceipt{UnitName: unit, BootID: bootAfter, RequestMonotonicNanos: start, FinishMonotonicNanos: finish, Status: "completed"}, nil
}

func (a *LocalNativeAuthority) Probe(ctx context.Context, request AccessProbeRequest) (AccessProbeResult, error) {
	if request.Validate() != nil || !a.qualified(request.UnitName) {
		return AccessProbeResult{}, errProbeBlocked
	}
	return ProbeReader(ctx, request)
}

type rejectCommandOutput struct{}

func (rejectCommandOutput) Write(p []byte) (int, error) {
	if len(p) > 0 {
		return 0, errProbeBlocked
	}
	return 0, nil
}

var _ io.Writer = rejectCommandOutput{}

func currentBootID() (string, error) {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", errProbeBlocked
	}
	boot := strings.TrimSpace(string(data))
	if !bootIDPattern.MatchString(boot) {
		return "", errProbeBlocked
	}
	return boot, nil
}

func monotonicNanos() (int64, error) {
	var ts unix.Timespec
	if unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts) != nil {
		return 0, errProbeBlocked
	}
	return ts.Sec*1e9 + ts.Nsec, nil
}
