//go:build linux

package cijobrunner

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/vegastack/vegastack-labs/internal/cijobguard"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"golang.org/x/sys/unix"
)

type Receipt struct {
	Stage, ContainerID, LogDigest string
	Stopped, VolumesRemoved       bool
	Cleanup                       CleanupChecks
}
type CleanupChecks struct{ Wait, Cgroup, RemoveContainers, RemoveVolumes bool }
type DockerConfig struct{ ExecutablePath, SocketPath, VSKPath string }
type Docker struct {
	config  DockerConfig
	profile RuntimeProfile
	network NetworkVerifier
}

func NewDocker(c DockerConfig, p RuntimeProfile, n NetworkVerifier) (*Docker, error) {
	if !filepath.IsAbs(c.ExecutablePath) || !filepath.IsAbs(c.SocketPath) || !filepath.IsAbs(c.VSKPath) {
		return nil, ErrBlocked
	}
	return &Docker{config: c, profile: p, network: n}, nil
}

const initCommand = "set -e; chmod 0700 /home/runner; chown 0:0 /vsk-ci /vsk-ci/vsk-labs; chmod 0755 /vsk-ci; chmod 0555 /vsk-ci/vsk-labs; printf '#!/bin/sh\\nexec /vsk-ci/vsk-labs ci-job-hook\\n' > /vsk-ci/job-started.sh; chmod 0555 /vsk-ci/job-started.sh; chown 1001:1001 /home/runner"

func mounts(v []string, toolsReadOnly bool) []string {
	a := []string{}
	for i, path := range []string{runnerRoot, runnerRoot + "/bin", runnerRoot + "/externals", toolsRoot} {
		m := "type=volume,src=" + v[i] + ",dst=" + path
		if i == 0 {
			m += ",volume-nocopy"
		}
		if i == 1 || i == 2 || i == 3 && toolsReadOnly {
			m += ",readonly"
		}
		a = append(a, "--mount", m)
	}
	return a
}
func baseArgs(p RuntimeProfile) []string {
	a := []string{"--platform", "linux/" + runtime.GOARCH, "--network", p.NetworkID, "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--memory", strconv.FormatInt(p.MemoryBytes, 10), "--memory-swap", strconv.FormatInt(p.MemoryBytes, 10), "--pids-limit", strconv.FormatInt(p.PidsLimit, 10), "--cpu-period", strconv.FormatInt(p.CPUPeriodMicros, 10), "--cpu-quota", strconv.FormatInt(p.CPUQuotaMicros, 10), "--log-driver", "none"}
	if !p.Offline {
		a = append(a, "--dns", p.DNSResolver)
	}
	return a
}
func jobCreateArgs(_ Spec, p RuntimeProfile, v []string, name string) []string {
	a := append([]string{"create", "--name", name, "--label", "vsk.ci.owner=" + name, "--interactive", "--user", "1001:1001", "--workdir", runnerRoot, "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=32m,uid=1001,gid=1001,mode=0700"}, baseArgs(p)...)
	a = append(a, mounts(v, true)...)
	return append(a, "--entrypoint", toolsRoot+"/vsk-labs", Image, PID1Mode)
}

type capBuffer struct {
	bytes.Buffer
	max int
}

func (b *capBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.max {
		return 0, ErrBlocked
	}
	return b.Buffer.Write(p)
}
func (d *Docker) cmd(ctx context.Context, args ...string) *exec.Cmd {
	a := append([]string{"--host", "unix://" + d.config.SocketPath}, args...)
	c := exec.CommandContext(ctx, d.config.ExecutablePath, a...)
	c.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "DOCKER_CONFIG=/nonexistent"}
	c.Stderr = io.Discard
	return c
}
func (d *Docker) command(ctx context.Context, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	var b capBuffer
	b.max = 64 << 10
	c := d.cmd(ctx, args...)
	c.Stdout = &b
	if c.Run() != nil {
		return "", ErrBlocked
	}
	return strings.TrimSpace(b.String()), nil
}
func fileDigest(path string) (string, error) {
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return "", ErrBlocked
	}
	f := os.NewFile(uintptr(fd), "protected executable")
	defer f.Close()
	s, e := f.Stat()
	if e != nil || !s.Mode().IsRegular() || s.Mode().Perm()&0022 != 0 || s.Mode().Perm()&0111 == 0 {
		return "", ErrBlocked
	}
	hash := sha256.New()
	if _, e = io.Copy(hash, io.LimitReader(f, 256<<20)); e != nil || s.Size() > 256<<20 {
		return "", ErrBlocked
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}
func (d *Docker) preflight(ctx context.Context, s Spec) error {
	p := d.profile
	if ValidateSpec(s, p) != nil || uint32(os.Geteuid()) != p.DaemonUID {
		return ErrBlocked
	}
	got, e := fileDigest(d.config.VSKPath)
	if e != nil || got != p.ExecutableDigest {
		return ErrBlocked
	}
	h := sha256.Sum256([]byte(HookScript))
	if "sha256:"+hex.EncodeToString(h[:]) != p.HookDigest {
		return ErrBlocked
	}
	infoCLI, e := os.Lstat(d.config.ExecutablePath)
	if e != nil || !infoCLI.Mode().IsRegular() || infoCLI.Sys().(*syscall.Stat_t).Uid != 0 {
		return ErrBlocked
	}
	if _, e = fileDigest(d.config.ExecutablePath); e != nil {
		return ErrBlocked
	}
	info, e := os.Lstat(d.config.SocketPath)
	if e != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0007 != 0 || info.Sys().(*syscall.Stat_t).Uid != p.DaemonUID {
		return ErrBlocked
	}
	raw, e := d.command(ctx, "info", "--format", "{{json .SecurityOptions}}|{{.CgroupVersion}}|{{.CgroupDriver}}")
	if e != nil || !strings.Contains(raw, "name=rootless") || !strings.HasSuffix(raw, "|2|systemd") {
		return ErrBlocked
	}
	arch, e := d.command(ctx, "image", "inspect", Image, "--format", "{{.Architecture}} {{.Os}}")
	if e != nil || (runtime.GOARCH != "arm64" && runtime.GOARCH != "amd64") || arch != runtime.GOARCH+" linux" {
		return ErrBlocked
	}
	if !p.Offline {
		if d.network == nil || d.network.Check(ctx, p, NetworkCheck{}) != nil {
			return ErrBlocked
		}
	}
	return nil
}
func (d *Docker) Run(ctx context.Context, s Spec, session Session) (receipt Receipt, runErr error) {
	receipt.Stage = "preflight"
	if ctx == nil || session == nil || d == nil || d.preflight(ctx, s) != nil {
		return receipt, ErrBlocked
	}
	ctx, cancel := context.WithDeadline(ctx, s.Deadline)
	defer cancel()
	var nonce [12]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		return receipt, ErrBlocked
	}
	name := "vsk-ci-" + hex.EncodeToString(nonce[:])
	vols := []string{}
	ids := []string{}
	var group *payload
	var stdin io.WriteCloser
	var events bytes.Buffer
	sequence := uint32(0)
	emit := func(stage string, code int) error {
		sequence++
		ev := LifecycleEvent{Stage: stage, Sequence: sequence, ExitCode: code}
		if !validEvent(ev) || hostaction.WriteFrame(&events, ev, 4096) != nil {
			return ErrProtocol
		}
		return session.Event(ctx, ev)
	}
	// Cleanup uses a separate finite context; cancellation never detaches a live job.
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		if stdin != nil {
			stdin.Close()
		}
		clean := true
		receipt.Cleanup = CleanupChecks{Wait: true, Cgroup: true, RemoveContainers: true, RemoveVolumes: true}
		for i := len(ids) - 1; i >= 0; i-- {
			id := ids[i]
			_, _ = d.command(cleanup, "kill", id)
			_, e := d.command(cleanup, "wait", id)
			if e != nil {
				clean = false
				receipt.Cleanup.Wait = false
			}
			if id == receipt.ContainerID && group != nil {
				if group.Kill(cleanup) != nil {
					receipt.Cleanup.Cgroup = false
					clean = false
				}
				group.Close()
			}
			if _, e = d.command(cleanup, "rm", id); e != nil {
				receipt.Cleanup.RemoveContainers = false
				clean = false
			}
		}
		receipt.Stopped = clean
		for _, v := range vols {
			if _, e := d.command(cleanup, "volume", "rm", v); e != nil {
				receipt.Cleanup.RemoveVolumes = false
				clean = false
			}
		}
		receipt.VolumesRemoved = clean
		sum := sha256.Sum256(events.Bytes())
		receipt.LogDigest = "sha256:" + hex.EncodeToString(sum[:])
		if !clean {
			runErr = ErrBlocked
		}
		if runErr == nil {
			receipt.Stage = "complete"
		}
	}()
	receipt.Stage = "volumes"
	for _, suffix := range []string{"root", "bin", "externals", "tools"} {
		v := name + "-" + suffix
		got, e := d.command(ctx, "volume", "create", "--label", "vsk.ci.owner="+name, v)
		if e != nil || got != v {
			return receipt, ErrBlocked
		}
		vols = append(vols, v)
	}
	p := d.profile
	p.NetworkID = "none"
	p.Offline = true
	initArgs := append([]string{"create", "--name", name + "-init", "--label", "vsk.ci.owner=" + name, "--user", "0:0", "--cap-add", "CHOWN"}, baseArgs(p)...)
	initArgs = append(initArgs, mounts(vols, false)...)
	initArgs = append(initArgs, "--entrypoint", "/bin/sh", Image, "-c", initCommand)
	receipt.Stage = "init_create"
	id, e := d.command(ctx, initArgs...)
	if e != nil || !dockerID(id) {
		return receipt, ErrBlocked
	}
	ids = append(ids, id)
	receipt.Stage = "init_copy"
	if e = d.copyExecutable(ctx, id); e != nil {
		return receipt, e
	}
	receipt.Stage = "init_start"
	if _, e = d.command(ctx, "start", "--attach", id); e != nil {
		return receipt, e
	}
	receipt.Stage = "init_exit"
	code, e := d.command(ctx, "inspect", id, "--format", "{{.State.ExitCode}}")
	if e != nil || code != "0" {
		return receipt, ErrBlocked
	}
	receipt.Stage = "prepared"
	if emit("prepared", 0) != nil {
		return receipt, ErrBlocked
	}
	receipt.Stage = "job_create"
	id, e = d.command(ctx, jobCreateArgs(s, d.profile, vols, name+"-job")...)
	if e != nil || !dockerID(id) {
		return receipt, ErrBlocked
	}
	ids = append(ids, id)
	receipt.ContainerID = id
	receipt.Stage = "job_attach"
	attach := d.cmd(ctx, "start", "--attach", "--interactive", id)
	in, e := attach.StdinPipe()
	if e != nil {
		return receipt, ErrBlocked
	}
	stdin = in
	out, writer, e := os.Pipe()
	attach.Stdout = writer
	if e != nil {
		return receipt, ErrBlocked
	}
	if attach.Start() != nil {
		out.Close()
		writer.Close()
		return receipt, ErrBlocked
	}
	writer.Close()
	defer out.Close()
	interrupt := context.AfterFunc(ctx, func() { out.Close(); in.Close() })
	defer interrupt()
	done := make(chan error, 1)
	go func() { done <- attach.Wait() }()
	// PID1 emits only framed platform protocol; raw child output is discarded inside it.
	stream := NewStream(out, in)
	f, e := stream.read(ctx)
	if e != nil || f.Kind != "ready" {
		return receipt, ErrBlocked
	}
	receipt.Stage = "job_verify"
	group, e = d.verifyPayload(ctx, id)
	if e != nil {
		return receipt, ErrBlocked
	}
	if !d.profile.Offline && d.network.Check(ctx, d.profile, NetworkCheck{ContainerID: id, InitPID: group.initPID}) != nil {
		return receipt, ErrBlocked
	}
	receipt.Stage = "started"
	if emit("started", 0) != nil {
		return receipt, ErrBlocked
	}
	if stream.write(ctx, frame{Kind: "start", Spec: &s}) != nil {
		return receipt, ErrProtocol
	}
	v, e := session.Registration(ctx)
	if e != nil {
		return receipt, e
	}
	if v == nil {
		return receipt, ErrProtocol
	}
	e = stream.write(ctx, frame{Kind: "registration", Token: v.Bytes()})
	v.Close()
	if e != nil {
		return receipt, e
	}
	// Cancellation of the authenticated stream is surfaced by Session methods. After
	// admission, its outer EOF is watched by the typed handler and cancels ctx.
	for {
		f, e = stream.read(ctx)
		if e != nil {
			return receipt, ErrBlocked
		}
		switch f.Kind {
		case "configured":
			if f.Runner == nil {
				return receipt, ErrProtocol
			}
			receipt.Stage = f.Runner.Stage
			if session.Configured(ctx, *f.Runner) != nil {
				return receipt, ErrProtocol
			}
			if emit(f.Runner.Stage, 0) != nil {
				return receipt, ErrProtocol
			}
		case "held":
			receipt.Stage = "held"
			if emit("held", 0) != nil {
				return receipt, ErrProtocol
			}
			decision, e := session.Held(ctx)
			if e != nil || ValidateDecision(s.Binding, decision) != nil {
				return receipt, ErrBlocked
			}
			if stream.write(ctx, frame{Kind: "decision", Decision: &decision}) != nil {
				return receipt, ErrProtocol
			}
			if emit("allowed", 0) != nil {
				return receipt, ErrProtocol
			}
		case "event":
			if f.Event == nil || f.Event.Stage != "failed" || !validEvent(*f.Event) {
				return receipt, ErrProtocol
			}
			if emit("failed", f.Event.ExitCode) != nil {
				return receipt, ErrProtocol
			}
		case "complete":
			if e = <-done; e != nil {
				return receipt, ErrBlocked
			}
			if emit("listener_exited", 0) != nil {
				return receipt, ErrProtocol
			}
			return receipt, nil
		default:
			return receipt, ErrProtocol
		}
	}
}
func dockerID(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, e := hex.DecodeString(s)
	return e == nil
}
func (d *Docker) verifyPayload(ctx context.Context, id string) (*payload, error) {
	raw, e := d.command(ctx, "inspect", id)
	if e != nil {
		return nil, ErrBlocked
	}
	var v []struct {
		ID    string `json:"Id"`
		State struct {
			Pid     int
			Running bool
		}
		Config     struct{ User string }
		HostConfig struct {
			NetworkMode         string
			ReadonlyRootfs      bool
			Privileged          bool
			PidMode             string
			Binds               []string
			Memory, MemorySwap  int64
			PidsLimit           int64
			CpuPeriod, CpuQuota int64
			LogConfig           struct{ Type string }
		}
	}
	if json.Unmarshal([]byte(raw), &v) != nil || len(v) != 1 {
		return nil, ErrBlocked
	}
	x := v[0]
	p := d.profile
	if x.ID != id || !x.State.Running || x.State.Pid < 2 || x.Config.User != "1001:1001" || x.HostConfig.NetworkMode != p.NetworkID || !x.HostConfig.ReadonlyRootfs || x.HostConfig.Privileged || x.HostConfig.PidMode != "" || len(x.HostConfig.Binds) != 0 || x.HostConfig.Memory != p.MemoryBytes || x.HostConfig.PidsLimit != p.PidsLimit || x.HostConfig.CpuPeriod != p.CPUPeriodMicros || x.HostConfig.CpuQuota != p.CPUQuotaMicros || x.HostConfig.LogConfig.Type != "none" {
		return nil, ErrBlocked
	}
	status, e := os.ReadFile(fmt.Sprintf("/proc/%d/status", x.State.Pid))
	if e != nil {
		return nil, ErrBlocked
	}
	for key, want := range map[string]string{"CapEff:": "0000000000000000", "NoNewPrivs:": "1", "Seccomp:": "2"} {
		found := false
		for _, line := range strings.Split(string(status), "\n") {
			parts := strings.Fields(line)
			if len(parts) == 2 && parts[0] == key && parts[1] == want {
				found = true
			}
		}
		if !found {
			return nil, ErrBlocked
		}
	}
	ours, e := os.Readlink("/proc/self/ns/pid")
	if e != nil {
		return nil, ErrBlocked
	}
	theirs, e := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", x.State.Pid))
	if e != nil || ours == theirs {
		return nil, ErrBlocked
	}
	cg, e := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", x.State.Pid))
	if e != nil {
		return nil, ErrBlocked
	}
	line := strings.TrimSpace(string(cg))
	if !strings.HasPrefix(line, "0::/") || strings.Contains(line, "\n") {
		return nil, ErrBlocked
	}
	rel := strings.TrimPrefix(line, "0::")
	if filepath.Base(rel) != "docker-"+id+".scope" || filepath.Clean(rel) != rel {
		return nil, ErrBlocked
	}
	// Docker's exact systemd scope must contain the inspected namespace init, not us.
	own, _ := os.ReadFile("/proc/self/cgroup")
	if strings.Contains(string(own), rel) {
		return nil, ErrBlocked
	}
	dir, e := os.Open(filepath.Join("/sys/fs/cgroup", rel))
	if e != nil {
		return nil, ErrBlocked
	}
	group, e := cijobguard.OpenCgroup(dir)
	if e != nil {
		dir.Close()
		return nil, e
	}
	fail := func() (*payload, error) { group.Close(); dir.Close(); return nil, ErrBlocked }
	writeFD, e := unix.Openat(int(dir.Fd()), "memory.oom.group", unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return fail()
	}
	_, e = unix.Write(writeFD, []byte("1"))
	unix.Close(writeFD)
	if e != nil {
		return fail()
	}
	for file, want := range map[string]string{"memory.oom.group": "1", "memory.max": strconv.FormatInt(p.MemoryBytes, 10), "memory.swap.max": "0", "pids.max": strconv.FormatInt(p.PidsLimit, 10), "cpu.max": fmt.Sprintf("%d %d", p.CPUQuotaMicros, p.CPUPeriodMicros)} {
		fd, e := unix.Openat(int(dir.Fd()), file, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			return fail()
		}
		f := os.NewFile(uintptr(fd), file)
		b, e := io.ReadAll(io.LimitReader(f, 512))
		f.Close()
		if e != nil || strings.TrimSpace(string(b)) != want {
			return fail()
		}
	}
	return &payload{group: group, directory: dir, path: filepath.Join("/sys/fs/cgroup", rel), initPID: x.State.Pid}, nil
}

// A removed cgroup directory is empty by the kernel rmdir contract. Keep its
// descriptor to distinguish removal of this exact subtree from a reused path.
type payload struct {
	initPID   int
	group     *cijobguard.Cgroup
	directory *os.File
	path      string
}

func (p *payload) Kill(ctx context.Context) error {
	info, e := p.directory.Stat()
	if e == nil && info.Sys().(*syscall.Stat_t).Nlink == 0 {
		return nil
	}
	if e := p.group.Kill(ctx); e == nil {
		return nil
	}
	// cgroupfs rmdir is permitted only after the exact subtree is empty. Docker
	// may remove it as soon as init exits, before our pinned kill write. Require
	// BOTH original path absence and this descriptor's kernel deleted identity;
	// absence alone, a reused path, or a failed kill is not success evidence.
	if _, e := os.Lstat(p.path); !os.IsNotExist(e) {
		return ErrBlocked
	}
	link, e := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", p.directory.Fd()))
	if e != nil || link != p.path+" (deleted)" {
		return ErrBlocked
	}
	return nil
}
func (p *payload) Close() { p.group.Close(); p.directory.Close() }

// copyExecutable hashes and archives one pinned file descriptor; Docker never
// reopens an unverified source path or receives a host bind mount.
func (d *Docker) copyExecutable(ctx context.Context, id string) error {
	fd, e := unix.Open(d.config.VSKPath, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return ErrBlocked
	}
	f := os.NewFile(uintptr(fd), "fixed executable")
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() > 256<<20 {
		return ErrBlocked
	}
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil || "sha256:"+hex.EncodeToString(h.Sum(nil)) != d.profile.ExecutableDigest {
		return ErrBlocked
	}
	if _, e = f.Seek(0, 0); e != nil {
		return ErrBlocked
	}
	// Snapshot after verifying. Binary updates cannot change bytes during tar copy.
	raw, e := io.ReadAll(io.LimitReader(f, 256<<20+1))
	if e != nil || int64(len(raw)) != info.Size() {
		return ErrBlocked
	}
	defer clear(raw)
	sum := sha256.Sum256(raw)
	if "sha256:"+hex.EncodeToString(sum[:]) != d.profile.ExecutableDigest {
		return ErrBlocked
	}
	r, w := io.Pipe()
	done := make(chan error, 1)
	go func() {
		tw := tar.NewWriter(w)
		e := tw.WriteHeader(&tar.Header{Name: "vsk-labs", Mode: 0555, Size: int64(len(raw)), Uid: 0, Gid: 0, Typeflag: tar.TypeReg})
		if e == nil {
			_, e = tw.Write(raw)
		}
		if e == nil {
			e = tw.Close()
		}
		w.CloseWithError(e)
		done <- e
	}()
	cmd := d.cmd(ctx, "cp", "-", id+":"+toolsRoot)
	cmd.Stdin = r
	cmd.Stdout = io.Discard
	e = cmd.Run()
	r.Close()
	archiveErr := <-done
	if e != nil || archiveErr != nil {
		return ErrBlocked
	}
	return nil
}
