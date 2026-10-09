//go:build linux

package linuxrole

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"golang.org/x/sys/unix"
)

const BoundaryProbeMode = "role-boundary-probe"

type boundaryObservation struct {
	Process           string `json:"process"`
	HelperCredential  string `json:"helperCredential"`
	ControlCredential string `json:"controlCredential"`
}

// RunBoundaryProbe is a non-root disposable read probe. It accepts a process
// identity only; credential paths are fixed and no content is ever returned.
func RunBoundaryProbe(pid int64, w io.Writer) error {
	if os.Getuid() == 0 || os.Getuid() != os.Geteuid() || pid < 2 {
		return errNative
	}
	observe := func(p string, allowAbsent bool) (string, error) {
		fd, e := unix.Open(p, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e == nil {
			unix.Close(fd)
			return "readable", errNative
		}
		if errors.Is(e, unix.EACCES) || errors.Is(e, unix.EPERM) {
			return "denied", nil
		}
		if allowAbsent && errors.Is(e, unix.ENOENT) {
			return "absent", nil
		}
		return "unavailable", errNative
	}
	var o boundaryObservation
	var e error
	o.Process, e = observe("/proc/"+strconv.FormatInt(pid, 10)+"/mem", false)
	if e != nil {
		return e
	}
	o.HelperCredential, e = observe("/etc/vsk-labs/host-action.json", false)
	if e != nil {
		return e
	}
	o.ControlCredential, e = observe(controlConfig, true)
	if e != nil {
		return e
	}
	return json.NewEncoder(w).Encode(o)
}
func (n *nativeRuntime) workloadIsolation(ctx context.Context, in generated.LinuxRoleInput) (any, error) {
	if n.root != "/" || len(in.Accounts) != 1 {
		return nil, errNative
	}
	a := in.Accounts[0]
	if a.UID == 65534 {
		return nil, errNative
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// The synthetic sleeper contains no secrets and executes no workload. Its
	// real kernel process belongs to the selected role UID; the negative reader
	// belongs to the distinct nobody UID and cannot inspect its address space.
	child := exec.CommandContext(ctx, "/usr/bin/sleep", "5")
	child.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	child.Dir = "/"
	child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(a.UID), Gid: uint32(a.GID), Groups: []uint32{}}}
	if child.Start() != nil {
		return nil, errNative
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	processProbe := exec.CommandContext(ctx, "/usr/local/bin/vsk-labs", BoundaryProbeMode, strconv.Itoa(child.Process.Pid))
	processProbe.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	processProbe.Dir = "/"
	processProbe.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}}
	var processOut boundedOutput
	processProbe.Stdout = &processOut
	processProbe.Stderr = io.Discard
	if processProbe.Run() != nil {
		return nil, errNative
	}
	var observed boundaryObservation
	if json.Unmarshal(processOut.Bytes(), &observed) != nil || observed.Process != "denied" || observed.HelperCredential != "denied" {
		return nil, errNative
	}
	// The role UID itself must also be denied privileged helper/control paths.
	ownProbe := exec.CommandContext(ctx, "/usr/local/bin/vsk-labs", BoundaryProbeMode, strconv.Itoa(os.Getpid()))
	ownProbe.Env = processProbe.Env
	ownProbe.Dir = "/"
	ownProbe.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(a.UID), Gid: uint32(a.GID), Groups: []uint32{}}}
	var ownOut boundedOutput
	ownProbe.Stdout = &ownOut
	ownProbe.Stderr = io.Discard
	if ownProbe.Run() != nil {
		return nil, errNative
	}
	var own boundaryObservation
	if json.Unmarshal(ownOut.Bytes(), &own) != nil || own.Process != "denied" || own.HelperCredential != "denied" {
		return nil, errNative
	}
	return map[string]any{"distinctUserProcess": observed, "roleCredentialBoundary": own, "roleUID": a.UID, "processStartDigest": hostaction.Digest(map[string]int{"pid": child.Process.Pid})}, nil
}
