//go:build linux || darwin

package debianbaseline

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"io"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strings"
	"syscall"
	"time"
)

type nativeRuntime struct {
	root, version string
	run           func(context.Context, string, []string, []byte) ([]byte, error)
	now           func() time.Time
}

func NewNativeRuntime(version string) Runtime {
	return &nativeRuntime{root: "/", version: version, run: baselineCommand, now: func() time.Time { return time.Now().UTC() }}
}

type outputLimit struct{ bytes.Buffer }

func (b *outputLimit) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 65536 {
		return 0, errBaseline
	}
	return b.Buffer.Write(p)
}
func baselineCommand(ctx context.Context, bin string, args []string, in []byte) ([]byte, error) {
	switch bin {
	case "/usr/bin/apt-config", "/usr/bin/dpkg", "/usr/sbin/iptables-nft", "/usr/sbin/ip6tables-nft", "/usr/bin/busctl", "/usr/bin/fail2ban-client", "/usr/sbin/auditctl", "/usr/sbin/augenrules", "/usr/sbin/aa-status", "/usr/sbin/apparmor_parser", "/usr/bin/systemctl", "/usr/bin/dpkg-query", "/usr/bin/timedatectl", "/usr/bin/chronyc", "/usr/bin/aide", "/usr/bin/gpgv", "/usr/bin/apt-get":
	default:
		return nil, errBaseline
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, bin, args...)
	c.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "DEBIAN_FRONTEND=noninteractive"}
	c.Dir = "/"
	c.Stdin = bytes.NewReader(in)
	var out outputLimit
	c.Stdout = &out
	c.Stderr = io.Discard
	if e := c.Run(); e != nil {
		return nil, errBaseline
	}
	return out.Bytes(), nil
}
func (n *nativeRuntime) Read(ctx context.Context, r ReadRequest) ([]byte, error) {
	switch r.Operation {
	case ReadConfig:
		p := map[string]string{"fail2ban-jail": "etc/fail2ban/jail.d/70-vsk-sshd.local", "fail2ban-action": "etc/fail2ban/action.d/vsk-sshd.conf", "auditd": "etc/audit/auditd.conf", "aide-config": "etc/vsk-labs/baseline/aide.conf", "aide-reference": "var/lib/vsk-labs/baseline/aide-reference.json", "aide-database": "var/lib/vsk-labs/baseline/aide.db"}[r.Selector]
		if p == "" {
			return nil, errBaseline
		}
		return protectedRead(n.root, p, 16<<20)
	case ReadProfile:
		if !safeName.MatchString(r.Selector) {
			return nil, errBaseline
		}
		return protectedRead(n.root, "etc/apparmor.d/"+r.Selector, 65536)
	case ReadKernel:
		allowed := map[string]bool{"kernel.randomize_va_space": true, "kernel.kptr_restrict": true, "kernel.dmesg_restrict": true, "kernel.yama.ptrace_scope": true, "fs.protected_hardlinks": true, "fs.protected_symlinks": true, "kernel.unprivileged_bpf_disabled": true}
		if !allowed[r.Selector] {
			return nil, errBaseline
		}
		return os.ReadFile(path.Join(n.root, "proc/sys", strings.ReplaceAll(r.Selector, ".", "/")))
	case ReadDisk:
		if !strings.HasPrefix(r.Selector, "/") || path.Clean(r.Selector) != r.Selector {
			return nil, errBaseline
		}
		var st syscall.Statfs_t
		if e := syscall.Statfs(path.Join(n.root, r.Selector), &st); e != nil {
			return nil, e
		}
		return json.Marshal(diskObservation{Total: uint64(st.Blocks) * uint64(st.Bsize), Free: uint64(st.Bavail) * uint64(st.Bsize)})
	case ReadAPT:
		return n.readAPT(ctx)
	}
	bin, args, e := readCommand(r)
	if e != nil {
		return nil, e
	}
	b, e := n.run(ctx, bin, args, nil)
	if e != nil {
		return nil, e
	}
	if r.Operation == ReadTime && r.Selector == "systemd-timesyncd" {
		return n.timeObservation(ctx, b)
	}
	return b, nil
}
func protectedRead(root, p string, limit int64) ([]byte, error) {
	if path.IsAbs(p) || path.Clean(p) != p || strings.HasPrefix(p, "../") {
		return nil, errBaseline
	}
	fs, e := os.OpenRoot(root)
	if e != nil {
		return nil, e
	}
	defer fs.Close()
	parts := strings.Split(p, "/")
	for i := range parts {
		st, e := fs.Lstat(strings.Join(parts[:i+1], "/"))
		if e != nil {
			return nil, e
		}
		if st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0022 != 0 {
			return nil, errBaseline
		}
		sys, ok := st.Sys().(*syscall.Stat_t)
		if !ok || sys.Uid != uint32(os.Geteuid()) && !(root == "/" && sys.Uid == 0) {
			return nil, errBaseline
		}
	}
	f, e := fs.Open(p)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() > limit {
		return nil, errBaseline
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) {
		return nil, errBaseline
	}
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(b)) > limit {
		return nil, errBaseline
	}
	return b, nil
}
func (n *nativeRuntime) Inspect(ctx context.Context, b generated.HostActionBundle, in generated.DebianBaselineInput) error {
	if n.root == "/" && (runtime.GOOS != "linux" || runtime.GOARCH != "amd64") {
		return errBaseline
	}
	if in.HostID != b.HostID || in.HostIdentityDigest != b.HostIdentityDigest || in.AutomationUID != int64(b.CallerUID) || in.ProfileLock.ExecutableVersion != n.version {
		return errBaseline
	}
	raw, e := protectedRead(n.root, "etc/vsk-labs/debian-profile.json", 65536)
	if e != nil {
		return e
	}
	var lock generated.DebianProfileLock
	if json.Unmarshal(raw, &lock) != nil || hostaction.Digest(lock) != in.ProfileLockDigest {
		return errBaseline
	}
	release, e := protectedRead(n.root, "etc/debian_version", 128)
	if e != nil || strings.TrimSpace(string(release)) != "13.6" {
		return errBaseline
	}
	for _, p := range in.ProfileLock.Packages {
		raw, e = n.Read(ctx, ReadRequest{Operation: ReadPackage, Selector: p.Name})
		if e != nil || strings.TrimSpace(string(raw)) != p.Version {
			return errBaseline
		}
	}
	return nil
}
func (n *nativeRuntime) Collect(ctx context.Context, b generated.HostActionBundle, in generated.DebianBaselineInput) (Result, error) {
	if e := n.Inspect(ctx, b, in); e != nil {
		return Result{}, e
	}
	m, e := Collect(ctx, in, n)
	return Result{Measurements: m}, e
}
