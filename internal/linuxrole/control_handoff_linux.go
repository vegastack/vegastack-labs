//go:build linux

package linuxrole

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const controlConfig = "/etc/vsk-labs/control/server.json"
const controlDatabase = "/var/lib/vsk-labs/control/control.db"
const controlSocket = "/run/vsk-labs-control/control.sock"
const handoffReceiptPath = "var/lib/vsk-labs/access-rollback/control-handoff.json"
const HandoffWorkerMode = "control-handoff-once"
const HandoffHealthMode = "control-handoff-health"

type HandoffReceipt struct {
	Bundle generated.HostActionBundle `json:"bundle"`
	Input  generated.LinuxRoleInput   `json:"input"`
	Status string                     `json:"status"`
	State  ControlServiceState        `json:"state"`
	Digest string                     `json:"digest"`
}

func (r HandoffReceipt) digest() string { r.Digest = ""; return hostaction.Digest(r) }
func (n *nativeRuntime) saveHandoff(r *HandoffReceipt) error {
	r.Digest = r.digest()
	b, e := json.Marshal(r)
	if e != nil || len(b) > 65536 {
		return errNative
	}
	return writeProtected(n.root, handoffReceiptPath, b)
}
func (n *nativeRuntime) readHandoff() (HandoffReceipt, error) {
	var r HandoffReceipt
	b, e := readProtected(n.root, handoffReceiptPath, 65536)
	if e != nil {
		return r, e
	}
	if json.Unmarshal(b, &r) != nil || r.Digest != r.digest() || ValidateInput(r.Input) != nil {
		return r, errNative
	}
	return r, nil
}
func (n *nativeRuntime) Handoff(ctx context.Context, b generated.HostActionBundle, in generated.LinuxRoleInput) (RoleResult, error) {
	out := RoleResult{}
	if in.Handoff == nil {
		return out, errNative
	}
	if b.ActionID == "debian.control.handoff.verify" {
		r, e := n.readHandoff()
		if e != nil || r.Status != "completed" || hostaction.Digest(r.Input.Handoff) != hostaction.Digest(in.Handoff) || r.Input.RoleBindingDigest != in.RoleBindingDigest {
			return out, errNative
		}
		s, e := n.handoffState(ctx, in)
		if e != nil || !s.ServiceActive || ValidateControlHandoff(in, s) != nil {
			out.Measurements = incompleteMeasurements(in, hostaction.Digest(b))
			return out, nil
		}
		return n.Collect(ctx, b, in)
	}
	e := n.withLock(ctx, func() error {
		expiry, e := time.Parse(time.RFC3339, b.ExpiresAt)
		deadline, e2 := time.Parse(time.RFC3339, in.Handoff.ExpiresAt)
		if e != nil || e2 != nil || !n.now().Before(expiry) || !n.now().Before(deadline) || deadline.After(expiry) {
			return errNative
		}
		if prior, e := n.readHandoff(); e == nil {
			if prior.Status != "completed" || prior.Input.HostID != in.HostID || prior.Input.Handoff.DatabaseInstanceID != in.Handoff.DatabaseInstanceID {
				return errNative
			}
		} else if !os.IsNotExist(e) {
			return e
		}
		s, e := n.handoffState(ctx, in)
		if e != nil || s.ServiceActive || ValidateControlHandoff(in, s) != nil {
			return errNative
		}
		receipt := HandoffReceipt{Bundle: b, Input: in, State: s, Status: "pending"}
		if e = n.saveHandoff(&receipt); e != nil {
			return e
		}
		out.Changed = true
		out.Pending = true
		_, e = n.run(ctx, "/usr/bin/systemd-run", []string{"--unit=vsk-control-handoff", "--collect", "--no-block", "--property=Type=oneshot", "--property=User=root", "--property=UMask=0077", "--property=TimeoutStartSec=90", "--property=Restart=no", "--", "/usr/local/bin/vsk-labs", HandoffWorkerMode})
		return e
	})
	return out, e
}

// RunControlHandoff consumes only a root-protected receipt written by an exact
// acknowledged host action. It never opens SQLite or changes any other service.
func RunControlHandoff(ctx context.Context, version string) error {
	if os.Geteuid() != 0 || os.Getuid() != 0 {
		return errNative
	}
	n := NewNativeRuntime(version).(*nativeRuntime)
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	for {
		e := n.runHandoff(ctx)
		if !errors.Is(e, unix.EWOULDBLOCK) {
			return e
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}
func (n *nativeRuntime) runHandoff(ctx context.Context) error {
	return n.withLock(ctx, func() error {
		r, e := n.readHandoff()
		if e != nil || r.Status != "pending" {
			return errNative
		}
		h := r.Input.Handoff
		if h == nil {
			return errNative
		}
		expiry, e := time.Parse(time.RFC3339, h.ExpiresAt)
		lease, e2 := time.Parse(time.RFC3339, r.Bundle.ExpiresAt)
		rollback, e3 := time.Parse(time.RFC3339, h.RollbackDeadline)
		if e != nil || e2 != nil || e3 != nil || !n.now().Before(expiry) || !n.now().Before(lease) || !n.now().Before(rollback) {
			return errNative
		}
		deadline := expiry
		if lease.Before(deadline) {
			deadline = lease
		}
		if rollback.Before(deadline) {
			deadline = rollback
		}
		ctx, cancel := context.WithDeadline(ctx, deadline)
		defer cancel()
		s, e := n.handoffState(ctx, r.Input)
		if e != nil || s.ServiceActive || ValidateControlHandoff(r.Input, s) != nil {
			return errNative
		}
		// pidfd pins the process across PID recycling; revalidate start identity after
		// opening it and signal that descriptor rather than the numeric PID.
		stop, closeProcess, e := n.prepareStop(h)
		if e != nil {
			return e
		}
		defer closeProcess()
		r.Status = "stopping"
		if e = n.saveHandoff(&r); e != nil {
			return e
		}
		fail := func() error { r.Status = "recovery-required"; _ = n.saveHandoff(&r); return errNative }
		if e = stop(ctx); e != nil {
			return fail()
		}
		if e = n.handoffWriterReleased(h.ServiceUID, h.WriterLockDigest); e != nil {
			return fail()
		}
		// Recheck protected unit/config/executable after the old writer exits.
		if e = n.handoffFiles(r.Input); e != nil {
			return fail()
		}
		r.Status = "starting"
		if e = n.saveHandoff(&r); e != nil {
			return fail()
		}
		if _, e = n.run(ctx, "/usr/bin/systemctl", []string{"enable", "vsk-labs.service"}); e != nil {
			return fail()
		}
		if _, e = n.run(ctx, "/usr/bin/systemctl", []string{"start", "vsk-labs.service"}); e != nil {
			return fail()
		}
		for {
			if ctx.Err() != nil {
				return fail()
			}
			s, e = n.handoffState(ctx, r.Input)
			if e == nil && s.ServiceActive && ValidateControlHandoff(r.Input, s) == nil && ctx.Err() == nil && n.now().Before(deadline) {
				r.State = s
				r.Status = "completed"
				return n.saveHandoff(&r)
			}
			select {
			case <-ctx.Done():
				return fail()
			case <-time.After(100 * time.Millisecond):
			}
		}
	})
}
func processStart(pid int64) (string, error) {
	raw, e := os.ReadFile("/proc/" + strconv.FormatInt(pid, 10) + "/stat")
	if e != nil {
		return "", e
	}
	end := strings.LastIndex(string(raw), ") ")
	if end < 0 {
		return "", errNative
	}
	f := strings.Fields(string(raw[end+2:]))
	if len(f) < 20 {
		return "", errNative
	}
	boot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil {
		return "", e
	}
	return hostaction.Digest(map[string]string{"boot": strings.TrimSpace(string(boot)), "start": f[19]}), nil
}
func ownedFile(p string, uid int64, limit int64) ([]byte, error) {
	if e := ownedAncestors(p, uid); e != nil {
		return nil, e
	}
	fd, e := unix.Open(p, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), p)
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || int64(st.Uid) != uid || st.Nlink != 1 || st.Mode&0022 != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size > limit {
		return nil, errNative
	}
	return io.ReadAll(io.LimitReader(f, limit+1))
}
func lockIdentity(uid int64) (string, *os.File, error) {
	p := controlDatabase + ".lock"
	if e := ownedAncestors(p, uid); e != nil {
		return "", nil, e
	}
	fd, e := unix.Open(p, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return "", nil, e
	}
	f := os.NewFile(uintptr(fd), p)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || int64(st.Uid) != uid || st.Nlink != 1 || st.Mode&0077 != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG {
		f.Close()
		return "", nil, errNative
	}
	return hostaction.Digest(map[string]any{"path": p, "device": st.Dev, "inode": st.Ino, "uid": st.Uid}), f, nil
}
func writerReleased(uid int64, expected string) error {
	digest, f, e := lockIdentity(uid)
	if e != nil {
		return e
	}
	defer f.Close()
	if digest != expected {
		return errNative
	}
	if e = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return e
	}
	return unix.Flock(int(f.Fd()), unix.LOCK_UN)
}
func (n *nativeRuntime) controlFiles(in generated.LinuxRoleInput) error {
	h := in.Handoff
	if h == nil {
		return errNative
	}
	if e := n.unitOverrides("vsk-labs.service"); e != nil {
		return e
	}
	if _, e := protectedInfo(n.root, "etc/systemd/system/multi-user.target.wants"); e != nil && !os.IsNotExist(e) {
		return e
	}
	enablePath := "/etc/systemd/system/multi-user.target.wants/vsk-labs.service"
	if st, e := os.Lstat(enablePath); e == nil {
		target, e := os.Readlink(enablePath)
		if e != nil || st.Mode()&os.ModeSymlink == 0 || target != "/etc/systemd/system/vsk-labs.service" {
			return errNative
		}
	} else if !os.IsNotExist(e) {
		return errNative
	}
	raw, e := readProtected(n.root, "etc/systemd/system/vsk-labs.service", 65536)
	if e != nil || hostaction.BytesDigest(raw) != h.UnitDigest || hostaction.BytesDigest(DesiredFiles(in)["etc/systemd/system/vsk-labs.service"]) != h.UnitDigest {
		return errNative
	}
	raw, e = readProtected(n.root, "usr/local/bin/vsk-labs", 128<<20)
	if e != nil || hostaction.BytesDigest(raw) != h.ExecutableDigest {
		return errNative
	}
	raw, e = ownedFile(controlConfig, h.ServiceUID, 65536)
	if e != nil || hostaction.BytesDigest(raw) != h.ConfigDigest {
		return errNative
	}
	var cfg struct {
		SocketPath     string `json:"socketPath"`
		SocketOwnerUID int64  `json:"socketOwnerUid"`
	}
	if json.Unmarshal(raw, &cfg) != nil || cfg.SocketPath != controlSocket || cfg.SocketOwnerUID != h.ServiceUID {
		return errNative
	}
	return nil
}
func (n *nativeRuntime) controlState(ctx context.Context, in generated.LinuxRoleInput) (ControlServiceState, error) {
	var s ControlServiceState
	h := in.Handoff
	if h == nil || n.controlFiles(in) != nil {
		return s, errNative
	}
	raw, e := n.run(ctx, "/usr/bin/systemctl", []string{"show", "vsk-labs.service", "--property=ActiveState,MainPID,User,FragmentPath,DropInPaths,UnitFileState", "--no-pager"})
	if e != nil {
		return s, e
	}
	props := parseProperties(raw)
	if props["FragmentPath"] != "/etc/systemd/system/vsk-labs.service" || props["DropInPaths"] != "" {
		return s, errNative
	}
	s.ServiceActive = props["ActiveState"] == "active"
	s.PID = h.ForegroundPID
	if s.ServiceActive {
		if props["UnitFileState"] != "enabled" {
			return s, errNative
		}
		s.PID, e = strconv.ParseInt(props["MainPID"], 10, 64)
		if e != nil || props["User"] != strconv.FormatInt(h.ServiceUID, 10) {
			return s, errNative
		}
	}
	s.StartIdentity, e = processStart(s.PID)
	if e != nil {
		return s, e
	}
	var st unix.Stat_t
	if unix.Stat("/proc/"+strconv.FormatInt(s.PID, 10), &st) != nil || int64(st.Uid) != h.ServiceUID {
		return s, errNative
	}
	s.ServiceUID = int64(st.Uid)
	exe, e := readProcessExecutable(s.PID)
	if e != nil || hostaction.BytesDigest(exe) != h.ExecutableDigest {
		return s, errNative
	}
	cmd, e := os.ReadFile("/proc/" + strconv.FormatInt(s.PID, 10) + "/cmdline")
	if e != nil || !strings.Contains(string(cmd), "server\x00run\x00") || !strings.Contains(string(cmd), "--config\x00"+controlConfig+"\x00") {
		return s, errNative
	}
	digest, f, e := lockIdentity(h.ServiceUID)
	if e != nil {
		return s, e
	}
	defer f.Close()
	if unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) == nil {
		unix.Flock(int(f.Fd()), unix.LOCK_UN)
		return s, errNative
	}
	if !processOwnsWriter(s.PID, f) {
		return s, errNative
	}
	s.WriterLockDigest = digest
	health, e := readControlHealth(ctx, h.ServiceUID, in.Accounts[0].GID)
	if e != nil || health.PID != s.PID {
		return s, errNative
	}
	s.DatabaseInstanceID = health.InstanceID
	s.RecoveryEpoch = health.RecoveryEpoch
	s.Healthy = health.State == "ready" && health.ReadAvailable && health.InstanceID != ""
	s.SocketIdentityDigest = health.SocketDigest
	s.UnitDigest = h.UnitDigest
	s.ConfigDigest = h.ConfigDigest
	s.ExecutableDigest = h.ExecutableDigest
	return s, nil
}

type controlHealth struct {
	State         string `json:"state"`
	ReadAvailable bool   `json:"readAvailable"`
	InstanceID    string `json:"instanceId"`
	RecoveryEpoch int64  `json:"recoveryEpoch"`
	SafeMode      bool   `json:"safeMode"`
	PID           int64  `json:"pid"`
	SocketDigest  string `json:"socketDigest"`
}

func readControlHealth(ctx context.Context, uid, gid int64) (controlHealth, error) {
	var h controlHealth
	c := exec.CommandContext(ctx, "/usr/local/bin/vsk-labs", HandoffHealthMode)
	c.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	c.Dir = "/"
	c.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}}}
	var out boundedOutput
	c.Stdout = &out
	c.Stderr = io.Discard
	if c.Run() != nil || json.Unmarshal(out.Bytes(), &h) != nil {
		return h, errNative
	}
	return h, nil
}

// WriteControlHealth uses the ordinary authorized API as the non-root service
// UID. The worker never reads the control database directly.
func WriteControlHealth(ctx context.Context, w io.Writer) error {
	if os.Getuid() == 0 || os.Getuid() != os.Geteuid() {
		return errNative
	}
	var st unix.Stat_t
	if unix.Lstat(controlSocket, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK || st.Uid != uint32(os.Geteuid()) || st.Mode&0077 != 0 {
		return errNative
	}
	var pid int64
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		c, e := (&net.Dialer{}).DialContext(ctx, "unix", controlSocket)
		if e != nil {
			return nil, e
		}
		uc, ok := c.(*net.UnixConn)
		if !ok {
			c.Close()
			return nil, errNative
		}
		sc, e := uc.SyscallConn()
		if e != nil {
			c.Close()
			return nil, e
		}
		var cred *unix.Ucred
		var ce error
		sc.Control(func(fd uintptr) { cred, ce = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
		if ce != nil || cred == nil || cred.Uid != uint32(os.Geteuid()) {
			c.Close()
			return nil, errNative
		}
		pid = int64(cred.Pid)
		return c, nil
	}}
	defer tr.CloseIdleConnections()
	client := http.Client{Transport: tr, Timeout: 3 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/api/v1/health", nil)
	resp, e := client.Do(req)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return errNative
	}
	var envelope struct {
		Data controlHealth `json:"data"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 65536)).Decode(&envelope) != nil || envelope.Data.InstanceID == "" {
		return errNative
	}
	h := envelope.Data
	h.PID = pid
	h.SocketDigest = hostaction.Digest(map[string]any{"path": controlSocket, "uid": st.Uid, "mode": st.Mode & 0777})
	return json.NewEncoder(w).Encode(h)
}

func ownedAncestors(p string, uid int64) error {
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	for i := 0; i < len(parts)-1; i++ {
		prefix := "/" + strings.Join(parts[:i+1], "/")
		var st unix.Stat_t
		if unix.Lstat(prefix, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&0022 != 0 {
			return errNative
		}
		allowService := prefix == "/etc/vsk-labs/control" || prefix == "/var/lib/vsk-labs/control"
		if st.Uid != 0 && (!allowService || int64(st.Uid) != uid) {
			return errNative
		}
	}
	return nil
}
func readProcessExecutable(pid int64) ([]byte, error) {
	f, e := os.Open("/proc/" + strconv.FormatInt(pid, 10) + "/exe")
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 128<<20+1))
	if e != nil || len(b) > 128<<20 {
		return nil, errNative
	}
	return b, nil
}
func processOwnsWriter(pid int64, lock *os.File) bool {
	var want unix.Stat_t
	if unix.Fstat(int(lock.Fd()), &want) != nil {
		return false
	}
	dir := "/proc/" + strconv.FormatInt(pid, 10) + "/fd"
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) > 8192 {
		return false
	}
	for _, entry := range entries {
		var st unix.Stat_t
		if unix.Stat(dir+"/"+entry.Name(), &st) != nil || st.Dev != want.Dev || st.Ino != want.Ino {
			continue
		}
		raw, e := os.ReadFile("/proc/" + strconv.FormatInt(pid, 10) + "/fdinfo/" + entry.Name())
		if e != nil || len(raw) > 65536 {
			return false
		}
		for _, line := range strings.Split(string(raw), "\n") {
			f := strings.Fields(line)
			if len(f) >= 8 && f[0] == "lock:" && f[2] == "FLOCK" && f[4] == "WRITE" && f[5] == strconv.FormatInt(pid, 10) {
				return true
			}
		}
	}
	return false
}

type handoffHooks struct {
	state       func(context.Context, generated.LinuxRoleInput) (ControlServiceState, error)
	prepareStop func(*generated.ControlHandoffInput) (func(context.Context) error, func(), error)
	files       func(generated.LinuxRoleInput) error
	released    func(int64, string) error
}

func (n *nativeRuntime) handoffState(ctx context.Context, in generated.LinuxRoleInput) (ControlServiceState, error) {
	if n.handoffHooks != nil && n.handoffHooks.state != nil {
		return n.handoffHooks.state(ctx, in)
	}
	return n.controlState(ctx, in)
}
func (n *nativeRuntime) handoffFiles(in generated.LinuxRoleInput) error {
	if n.handoffHooks != nil && n.handoffHooks.files != nil {
		return n.handoffHooks.files(in)
	}
	return n.controlFiles(in)
}
func (n *nativeRuntime) handoffWriterReleased(uid int64, d string) error {
	if n.handoffHooks != nil && n.handoffHooks.released != nil {
		return n.handoffHooks.released(uid, d)
	}
	return writerReleased(uid, d)
}
func (n *nativeRuntime) prepareStop(h *generated.ControlHandoffInput) (func(context.Context) error, func(), error) {
	if n.handoffHooks != nil && n.handoffHooks.prepareStop != nil {
		return n.handoffHooks.prepareStop(h)
	}
	fd, e := unix.PidfdOpen(int(h.ForegroundPID), 0)
	if e != nil {
		return nil, nil, e
	}
	closeFD := func() { unix.Close(fd) }
	start, e := processStart(h.ForegroundPID)
	if e != nil || start != h.ForegroundStartIdentity {
		closeFD()
		return nil, nil, errNative
	}
	stop := func(ctx context.Context) error {
		if unix.PidfdSendSignal(fd, unix.SIGTERM, nil, 0) != nil {
			return errNative
		}
		for {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			ready, e := unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}, 100)
			if e != nil {
				return e
			}
			if ready > 0 {
				return nil
			}
		}
	}
	return stop, closeFD, nil
}
