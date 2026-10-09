//go:build linux

package qualification

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"syscall"
	"time"
)

// NativeTransportProbe selects only a root-installed exact-plan fixture probe.
// Absence of the installed native scope leaves ordinary transport unchanged.
func NativeTransportProbe(ctx context.Context, b generated.HostActionBundle) (string, error) {
	if _, err := os.Lstat("/etc/vsk-labs/native/scope.json"); os.IsNotExist(err) {
		return "", nil
	}
	value, err := LoadServerScope(ctx)
	if err != nil {
		return "", err
	}
	scope, err := validateScope(value)
	if err != nil {
		return "", err
	}
	selected := ""
	for _, scenario := range []string{"action-replay", "action-concurrency"} {
		path := "/etc/vsk-labs/native/" + scenario + ".transport.json"
		fd, e := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return "", ErrUnavailable
		}
		f := os.NewFile(uintptr(fd), path)
		info, e := f.Stat()
		if e != nil {
			f.Close()
			return "", ErrUnavailable
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || st.Gid != uint32(value.ControlServiceGID) || st.Nlink != 1 || !info.Mode().IsRegular() || info.Mode().Perm() != 0640 || info.Size() > 16384 {
			f.Close()
			return "", ErrUnavailable
		}
		raw, e := io.ReadAll(io.LimitReader(f, 16385))
		f.Close()
		var in generated.NativeStepRequest
		if e != nil || len(raw) > 16384 || generated.ValidateContractJSON(generated.SchemaIDNativeStepRequest, raw, generated.ContractExact) != nil || json.Unmarshal(raw, &in) != nil {
			return "", ErrUnavailable
		}
		if in.PlanID != b.PlanID {
			continue
		}
		if validateStep(scope, in, time.Now().UTC()) != nil || in.Operation != "execute" || in.ScenarioID != scenario || in.PlanDigest != b.PlanDigest || in.RecoveryEpoch != b.RecoveryEpoch || scope.guests[in.GuestID].HostID != b.HostID || scope.guests[in.GuestID].HostIdentityDigest != b.HostIdentityDigest || b.ActionID != "debian.access.collect" || selected != "" {
			return "", ErrUnavailable
		}
		selected = scenario
	}
	if selected != "" {
		measured, e := fileDigest("/proc/self/exe", 256*1024*1024)
		var input generated.DebianAccessInput
		if e != nil || measured != value.ExecutableDigest || generated.ValidateContractJSON(generated.SchemaIDDebianAccessInput, []byte(b.ActionInput), generated.ContractExact) != nil || json.Unmarshal([]byte(b.ActionInput), &input) != nil || input.ProfileID != value.ProfileID || input.ProfileLockDigest != value.ProfileLockDigest {
			return "", ErrUnavailable
		}
	}
	return selected, nil
}
