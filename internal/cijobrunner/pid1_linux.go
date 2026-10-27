//go:build linux

package cijobrunner

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/vegastack/vegastack-labs/internal/runnerbootstrap"
	"golang.org/x/sys/unix"
)

// RunPID1 must be invoked only as private PID-namespace init. The executable
// caller MUST os.Exit on return: init death is the complete-job abort primitive.
func RunPID1(ctx context.Context, spec Spec, session Session) (runErr error) {
	phase := 1
	defer func() {
		if runErr != nil && session != nil {
			_ = session.Event(ctx, LifecycleEvent{Stage: "failed", Sequence: 1, ExitCode: phase})
		}
	}()
	if os.Getpid() != 1 || os.Geteuid() != 1001 || validateLaunch(spec) != nil || session == nil {
		return ErrBlocked
	}
	ctx, cancel := context.WithDeadline(ctx, spec.Deadline)
	defer cancel()
	phase = 2
	for _, p := range []string{runnerRoot + "/bin", runnerRoot + "/externals", toolsRoot} {
		var s unix.Statfs_t
		if unix.Statfs(p, &s) != nil || s.Flags&unix.ST_RDONLY == 0 {
			return ErrBlocked
		}
	}
	phase = 3
	if _, e := os.Lstat(hookSocket); !os.IsNotExist(e) {
		return ErrBlocked
	}
	sock, e := net.ListenUnix("unix", &net.UnixAddr{Name: hookSocket, Net: "unix"})
	if e != nil {
		return ErrBlocked
	}
	defer sock.Close()
	defer os.Remove(hookSocket)
	if os.Chmod(hookSocket, 0600) != nil {
		return ErrBlocked
	}
	phase = 4
	token, e := session.Registration(ctx)
	if e != nil {
		return e
	}
	phase = 5
	r, e := runnerbootstrap.Configure(ctx, runnerbootstrap.Config{Directory: runnerRoot, Organization: spec.Organization, Name: spec.RunnerName, Group: spec.RunnerGroup, Labels: append([]string(nil), spec.Labels...), ExpiresAt: spec.Deadline, Check: func() error { return ctx.Err() }}, token)
	token.Close()
	configured := ConfiguredRunner{Stage: r.Stage}
	if e == nil {
		configured, e = readConfigured(spec.RunnerName)
	}
	if r.Stage != "" {
		if send := session.Configured(ctx, configured); send != nil {
			return send
		}
	}
	if e != nil {
		return ErrBlocked
	}
	phase = 6
	listener := exec.CommandContext(ctx, runnerRoot+"/bin/Runner.Listener", "run", "--startuptype", "service")
	listener.Dir = runnerRoot
	listener.Env = runnerEnvironment()
	listener.Stdout = io.Discard
	listener.Stderr = io.Discard
	if listener.Start() != nil {
		return ErrBlocked
	}
	defer listener.Process.Kill()
	done := make(chan error, 1)
	go func() { done <- listener.Wait() }()
	phase = 7
	held := make(chan error, 1)
	go func() {
		conn, e := sock.AcceptUnix()
		if e != nil {
			held <- ErrBlocked
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(spec.Deadline)
		// No workflow process exists before this fixed hook. Only its one connection is accepted.
		if _, e := conn.Read(make([]byte, 1)); e != io.EOF {
			held <- ErrProtocol
			return
		}
		d, e := session.Held(ctx)
		if e != nil || ValidateDecision(spec.Binding, d) != nil {
			held <- ErrBlocked
			return
		}
		if e = writeHookDecision(conn, d); e != nil {
			held <- e
			return
		}
		held <- nil
	}()
	stop := context.AfterFunc(ctx, func() { sock.Close() })
	defer stop()
	select {
	case <-ctx.Done():
		return ErrBlocked
	case e := <-done:
		if e != nil {
			return ErrBlocked
		}
		return ErrBlocked // no job admitted
	case e := <-held:
		if e != nil {
			return e
		}
	}
	// After one allow the outer writer stays open until completion. Any subsequent
	// frame/EOF is cancellation, never another admission. No concurrent reader before allow.
	phase = 8
	lost := make(chan struct{}, 1)
	if stream, ok := session.(*Stream); ok {
		go func() { _, _ = stream.read(ctx); lost <- struct{}{} }()
	}
	select {
	case <-ctx.Done():
		return ErrBlocked
	case <-lost:
		return ErrBlocked
	case e := <-done:
		if e != nil {
			return ErrBlocked
		}
		return nil
	}
}
func runnerEnvironment() []string {
	return []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=" + runnerRoot, "LANG=C.UTF-8", "DOTNET_CLI_TELEMETRY_OPTOUT=1", "ACTIONS_RUNNER_HOOK_JOB_STARTED=" + toolsRoot + "/job-started.sh"}
}
func readConfigured(name string) (ConfiguredRunner, error) {
	fd, e := unix.Open(filepath.Join(runnerRoot, ".runner"), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return ConfiguredRunner{}, ErrBlocked
	}
	f := os.NewFile(uintptr(fd), "settings")
	defer f.Close()
	s, e := f.Stat()
	if e != nil || !s.Mode().IsRegular() || s.Size() > 16<<10 || s.Mode().Perm()&0022 != 0 {
		return ConfiguredRunner{}, ErrBlocked
	}
	var v struct {
		AgentID   uint64 `json:"agentId"`
		AgentName string `json:"agentName"`
	}
	raw, e := io.ReadAll(io.LimitReader(f, 16<<10+1))
	defer clear(raw)
	if e != nil || json.Unmarshal(raw, &v) != nil || v.AgentID == 0 || v.AgentName != name {
		return ConfiguredRunner{}, ErrBlocked
	}
	return ConfiguredRunner{Stage: "configured", RunnerID: v.AgentID, RunnerName: v.AgentName}, nil
}

// RunEntrypoint is the finite private stdin/stdout entry. No token is accepted in
// an argument or environment. It is not a public launch or authorization route.
func RunEntrypoint(ctx context.Context, input io.ReadCloser, output io.Writer) error {
	if os.Getpid() != 1 || os.Geteuid() != 1001 {
		return ErrBlocked
	}
	ctx, cancel := context.WithTimeout(ctx, time.Hour)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { input.Close() })
	defer stop()
	stream := NewStream(input, output)
	stream.ready = true
	if stream.write(ctx, frame{Kind: "ready"}) != nil {
		return ErrProtocol
	}
	f, e := stream.read(ctx)
	if e != nil || f.Kind != "start" {
		return ErrProtocol
	}
	if e := RunPID1(ctx, *f.Spec, stream); e != nil {
		return e
	}
	return stream.write(ctx, frame{Kind: "complete"})
}

// terminateInit does not return a failed hook. If signaling init fails it stays
// held until the independent outer finite supervisor terminates the namespace.
func terminateInit() error {
	_ = syscall.Kill(1, syscall.SIGTERM)
	for {
		time.Sleep(time.Hour)
	}
}
