//go:build linux

package runnerbootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/strictjson"
	"golang.org/x/sys/unix"
)

// Source pin: actions/runner d1eb12d4b115c301201de27d667284e1a80f2ab5,
// CommandSettings.GetRunnerRegisterToken and PromptManager.ReadValue.
const registrationPrompt = "What is your runner register token? "

// Configure executes only the caller-installed fixed Runner.Listener. Installation
// provenance, network sandbox, removal and later provider observation are owned by
// the caller. No child output, token or provider response is returned.
func Configure(ctx context.Context, c Config, v *credentialref.Value) (Receipt, error) {
	out := Receipt{}
	if ctx == nil || !validConfig(c, v) {
		return out, errInput
	}
	c.Labels = append([]string(nil), c.Labels...)
	if err := current(ctx, c); err != nil {
		return out, err
	}
	if !validInstallation(c.Directory) {
		return out, errInput
	}
	ctx, cancel := context.WithDeadline(ctx, c.ExpiresAt)
	defer cancel()
	ctx, budget := context.WithTimeout(ctx, 2*time.Minute)
	defer budget()
	master, slave, err := terminal()
	if err != nil {
		return out, errUnavailable
	}
	defer master.Close()
	defer slave.Close()
	masterFD := int(master.Fd())
	if unix.SetNonblock(masterFD, true) != nil {
		return out, errUnavailable
	}
	args := []string{"configure", "--url", "https://github.com/" + c.Organization, "--name", c.Name, "--runnergroup", c.Group, "--labels", strings.Join(c.Labels, ","), "--work", "_work", "--ephemeral", "--disableupdate", "--no-default-labels"}
	cmd := exec.Command(filepath.Join(c.Directory, "bin", "Runner.Listener"), args...)
	cmd.Dir = c.Directory
	cmd.Env = []string{}
	cmd.Stdin = slave
	cmd.Stdout = slave
	cmd.Stderr = slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := current(ctx, c); err != nil {
		return out, err
	}
	out.Stage = "registration_attempted"
	if cmd.Start() != nil {
		return out, errUnavailable
	}
	slave.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	reaped := false
	defer func() {
		_ = unix.Kill(-cmd.Process.Pid, unix.SIGKILL)
		if !reaped {
			<-done
		}
	}()
	line := make([]byte, 0, 4096)
	defer func() { clear(line[:cap(line)]) }()
	buf := make([]byte, 1024)
	defer clear(buf)
	sent := false
	total := 0
	exited := false
	var processErr error
	for {
		if err := current(ctx, c); err != nil {
			return out, err
		}
		select {
		case processErr = <-done:
			reaped = true
			exited = true
			_ = unix.Kill(-cmd.Process.Pid, unix.SIGKILL)
		default:
		}
		n, readErr := unix.Read(masterFD, buf)
		if n > 0 {
			total += n
			if total > 64<<10 {
				return out, errIntegrity
			}
			for _, b := range buf[:n] {
				if b == '\r' {
					continue
				}
				if b == '\n' {
					clear(line)
					line = line[:0]
					continue
				}
				if b < 32 && b != '\t' {
					return out, errIntegrity
				}
				line = append(line, b)
				if len(line) > 4096 {
					return out, errIntegrity
				}
				if bytes.Contains(line, v.Bytes()) {
					return out, errIntegrity
				}
				if string(line) == registrationPrompt {
					if sent {
						return out, errIntegrity
					}
					if err := current(ctx, c); err != nil {
						return out, err
					}
					if !validToken(v) || hideEcho(masterFD) != nil {
						return out, errIntegrity
					}
					if err := writeTerminal(ctx, masterFD, v.Bytes()); err != nil {
						return out, err
					}
					if err := writeTerminal(ctx, masterFD, []byte{'\r'}); err != nil {
						return out, err
					}
					sent = true
					out.Stage = "registration_secret_delivered"
					clear(line)
					line = line[:0]
				} else if (bytes.ContainsAny(line, "?:") && !strings.HasPrefix(registrationPrompt, string(line))) || bytes.Contains(line, []byte("Enter ")) || bytes.Contains(line, []byte("[press Enter")) {
					return out, errIntegrity
				}
			}
			clear(buf[:n])
			continue
		}
		if readErr != nil && readErr != unix.EAGAIN && readErr != unix.EWOULDBLOCK && readErr != unix.EIO {
			return out, errUnavailable
		}
		if exited {
			if processErr != nil || !sent {
				return out, errIntegrity
			}
			if err := current(ctx, c); err != nil {
				return out, err
			}
			if !verifySettings(ctx, c) {
				return out, errIntegrity
			}
			out.Stage = "configured"
			return out, nil
		}
		fds := []unix.PollFd{{Fd: int32(masterFD), Events: unix.POLLIN}}
		if _, err := unix.Poll(fds, 20); err != nil && err != unix.EINTR {
			return out, errUnavailable
		}
	}
}
func validToken(v *credentialref.Value) bool {
	b := v.Bytes()
	if len(b) == 0 || len(b) > 4096 {
		return false
	}
	for _, c := range b {
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}
func writeTerminal(ctx context.Context, fd int, b []byte) error {
	for len(b) > 0 {
		if ctx.Err() != nil {
			return errInterrupted
		}
		n, err := unix.Write(fd, b)
		if n > 0 {
			b = b[n:]
		}
		if err != nil && err != unix.EAGAIN && err != unix.EINTR {
			return errUnavailable
		}
		if n == 0 {
			unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}, 20)
		}
	}
	return nil
}
func terminal() (*os.File, *os.File, error) {
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	m := os.NewFile(uintptr(fd), "runner-registration-pty")
	fail := func(err error) (*os.File, *os.File, error) { m.Close(); return nil, nil, err }
	if err = unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		return fail(err)
	}
	number, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		return fail(err)
	}
	sfd, err := unix.Open(fmt.Sprintf("/dev/pts/%d", number), unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fail(err)
	}
	s := os.NewFile(uintptr(sfd), "runner-registration-terminal")
	if unix.Fchmod(sfd, 0600) != nil || hideEcho(sfd) != nil {
		s.Close()
		return fail(errIntegrity)
	}
	if unix.IoctlSetWinsize(sfd, unix.TIOCSWINSZ, &unix.Winsize{Row: 24, Col: 80}) != nil {
		s.Close()
		return fail(errIntegrity)
	}
	return m, s, nil
}
func hideEcho(fd int) error {
	term, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return err
	}
	term.Lflag &^= unix.ECHO | unix.ECHONL
	return unix.IoctlSetTermios(fd, unix.TCSETS, term)
}
func owned(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uint32(os.Geteuid()) && st.Nlink == 1 && info.Mode().Perm()&0022 == 0
}
func validInstallation(dir string) bool {
	if len(dir) == 0 || len(dir) > 4096 || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return false
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil || resolved != dir {
		return false
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) {
		return false
	}
	bin := filepath.Join(dir, "bin")
	info, err = os.Lstat(bin)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
		return false
	}
	st, ok = info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) {
		return false
	}
	exe := filepath.Join(bin, "Runner.Listener")
	info, err = os.Lstat(exe)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0100 == 0 || !owned(info) {
		return false
	}
	for _, name := range []string{".runner", ".credentials", ".credentials_rsaparams"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			return false
		}
	}
	return true
}
func verifySettings(ctx context.Context, c Config) bool {
	fd, err := unix.Open(filepath.Join(c.Directory, ".runner"), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	f := os.NewFile(uintptr(fd), "runner-settings")
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || !owned(info) || info.Size() < 1 || info.Size() > 16<<10 {
		return false
	}
	raw, err := io.ReadAll(io.LimitReader(f, 16<<10+1))
	defer clear(raw)
	if err != nil || len(raw) > 16<<10 || strictjson.Scan(ctx, raw, strictjson.Limits{MaxDepth: 8}) != nil {
		return false
	}
	var settings struct {
		AgentID       uint64 `json:"agentId"`
		AgentName     string `json:"agentName"`
		PoolID        uint64 `json:"poolId"`
		PoolName      string `json:"poolName"`
		GitHubURL     string `json:"gitHubUrl"`
		WorkFolder    string `json:"workFolder"`
		Ephemeral     bool   `json:"ephemeral"`
		DisableUpdate bool   `json:"disableUpdate"`
	}
	if json.Unmarshal(raw, &settings) != nil {
		return false
	}
	return settings.AgentID > 0 && settings.PoolID > 0 && settings.AgentName == c.Name && settings.PoolName == c.Group && settings.GitHubURL == "https://github.com/"+c.Organization && settings.WorkFolder == "_work" && settings.Ephemeral && settings.DisableUpdate
}
