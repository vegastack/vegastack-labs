//go:build linux

package linuxrole

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/debianbaseline"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"golang.org/x/sys/unix"
)

type nativeRuntime struct {
	root, version string
	run           func(context.Context, string, []string) ([]byte, error)
	now           func() time.Time
	handoffHooks  *handoffHooks
}

func NewNativeRuntime(version string) Runtime {
	return &nativeRuntime{root: "/", version: version, run: roleCommand, now: time.Now}
}

type boundedOutput struct{ bytes.Buffer }

func (b *boundedOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 65536 {
		return 0, errNative
	}
	return b.Buffer.Write(p)
}
func roleCommand(ctx context.Context, bin string, args []string) ([]byte, error) {
	switch bin {
	case "/usr/bin/getent", "/usr/bin/id", "/usr/sbin/groupadd", "/usr/sbin/useradd", "/usr/bin/systemctl", "/usr/bin/systemd-run", "/usr/bin/systemd-tmpfiles", "/usr/bin/setpriv", "/usr/bin/stat":
	default:
		return nil, errNative
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, bin, args...)
	c.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	c.Dir = "/"
	var b boundedOutput
	c.Stdout = &b
	c.Stderr = io.Discard
	if c.Run() != nil {
		return nil, errNative
	}
	return b.Bytes(), nil
}
func (n *nativeRuntime) Inspect(ctx context.Context, b generated.HostActionBundle, in generated.LinuxRoleInput) error {
	if in.HostID != b.HostID || in.HostIdentityDigest != b.HostIdentityDigest || in.AutomationUID != b.CallerUID || in.ProfileLock.ExecutableVersion != n.version {
		return errNative
	}
	// The existing baseline inspector binds Debian release, package pins and the
	// root-owned installed profile. It performs no baseline installation.
	if n.root == "/" {
		return debianbaseline.NewNativeRuntime(n.version).Inspect(ctx, b, generated.DebianBaselineInput{HostID: in.HostID, HostIdentityDigest: in.HostIdentityDigest, AutomationUID: in.AutomationUID, ProfileLock: in.ProfileLock, ProfileLockDigest: in.ProfileLockDigest})
	}
	return nil
}
func protectedInfo(root, p string) (os.FileInfo, error) {
	if path.IsAbs(p) || path.Clean(p) != p || p == "." || strings.HasPrefix(p, "../") {
		return nil, errNative
	}
	fs, e := os.OpenRoot(root)
	if e != nil {
		return nil, e
	}
	defer fs.Close()
	parts := strings.Split(p, "/")
	var st os.FileInfo
	for i := range parts {
		st, e = fs.Lstat(strings.Join(parts[:i+1], "/"))
		if e != nil {
			return nil, e
		}
		// os.FileInfo uses syscall.Stat_t; Fstat below avoids platform type aliases.
		if st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0022 != 0 {
			return nil, errNative
		}
		f, e := fs.OpenFile(strings.Join(parts[:i+1], "/"), os.O_RDONLY|unix.O_NOFOLLOW, 0)
		if e != nil {
			return nil, e
		}
		var u unix.Stat_t
		e = unix.Fstat(int(f.Fd()), &u)
		f.Close()
		if e != nil || u.Uid != uint32(os.Geteuid()) {
			return nil, errNative
		}
		if i < len(parts)-1 && !st.IsDir() {
			return nil, errNative
		}
	}
	return st, nil
}
func readProtected(root, p string, limit int64) ([]byte, error) {
	st, e := protectedInfo(root, p)
	if e != nil {
		return nil, e
	}
	if !st.Mode().IsRegular() || st.Size() > limit {
		return nil, errNative
	}
	fs, e := os.OpenRoot(root)
	if e != nil {
		return nil, e
	}
	defer fs.Close()
	f, e := fs.OpenFile(p, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	var u unix.Stat_t
	if unix.Fstat(int(f.Fd()), &u) != nil || u.Nlink != 1 || u.Uid != uint32(os.Geteuid()) {
		return nil, errNative
	}
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(b)) > limit {
		return nil, errNative
	}
	return b, nil
}
func writeProtected(root, p string, b []byte) error {
	if _, e := protectedInfo(root, path.Dir(p)); e != nil {
		return e
	}
	if _, e := readProtected(root, p, 65536); e != nil && !os.IsNotExist(e) {
		return e
	}
	fs, e := os.OpenRoot(root)
	if e != nil {
		return e
	}
	defer fs.Close()
	tmp := p + ".vsk-role-new"
	f, e := fs.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
	if e != nil {
		return e
	}
	defer fs.Remove(tmp)
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	if e = fs.Rename(tmp, p); e != nil {
		return e
	}
	d, e := fs.Open(path.Dir(p))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}

// The access rollback serialization lock also excludes role changes from an
// in-flight firewall/baseline restoration. No unrelated services are restarted.
func (n *nativeRuntime) withLock(ctx context.Context, fn func() error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	p := "var/lib/vsk-labs/access-rollback"
	if _, e := protectedInfo(n.root, p); e != nil {
		return e
	}
	fs, e := os.OpenRoot(n.root)
	if e != nil {
		return e
	}
	defer fs.Close()
	f, e := fs.OpenFile(p+"/lock", os.O_RDWR|os.O_CREATE|unix.O_NOFOLLOW, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(int(f.Fd()), &st) != nil || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) || st.Mode&0077 != 0 {
		return errNative
	}
	if e = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return e
	}
	defer unix.Flock(int(f.Fd()), unix.LOCK_UN)
	if raw, e := readProtected(n.root, p+"/record.json", 65536); e == nil {
		var state struct {
			State string `json:"state"`
		}
		if json.Unmarshal(raw, &state) != nil || state.State == "armed" || state.State == "uncertain" || state.State == "services-pending" {
			return errNative
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	return fn()
}
func (n *nativeRuntime) account(ctx context.Context, a generated.LinuxRoleAccount, create bool) (bool, error) {
	name := AccountName(a.Selector)
	if name == "" {
		return false, errNative
	}
	raw, e := n.run(ctx, "/usr/bin/getent", []string{"passwd", name})
	if e == nil {
		f := strings.Split(strings.TrimSpace(string(raw)), ":")
		if len(f) != 7 || f[0] != name || f[2] != strconv.FormatInt(a.UID, 10) || f[3] != strconv.FormatInt(a.GID, 10) || (a.Selector != "control" && (f[5] != "/nonexistent" || f[6] != "/usr/sbin/nologin")) || (a.Selector == "control" && f[6] != "/usr/sbin/nologin" && f[6] != "/bin/bash" && f[6] != "/bin/sh") {
			return false, errNative
		}
		groups, e := n.run(ctx, "/usr/bin/id", []string{"-G", name})
		if e != nil || strings.TrimSpace(string(groups)) != strconv.FormatInt(a.GID, 10) {
			return false, errNative
		}
		return false, nil
	}
	if a.Existing || !create {
		return false, errNative
	}
	// NSS itself must be available. A missing individual key is distinguished
	// from a broken backend by checking the complete bounded account databases.
	all, e := n.run(ctx, "/usr/bin/getent", []string{"passwd"})
	if e != nil {
		return false, e
	}
	for _, line := range strings.Split(string(all), "\n") {
		f := strings.Split(line, ":")
		if len(f) >= 4 && (f[0] == name || f[2] == strconv.FormatInt(a.UID, 10)) {
			return false, errNative
		}
	}
	groups, e := n.run(ctx, "/usr/bin/getent", []string{"group"})
	if e != nil {
		return false, e
	}
	for _, line := range strings.Split(string(groups), "\n") {
		f := strings.Split(line, ":")
		if len(f) >= 3 && (f[0] == name || f[2] == strconv.FormatInt(a.GID, 10)) {
			return false, errNative
		}
	}
	if _, e = n.run(ctx, "/usr/sbin/groupadd", []string{"--gid", strconv.FormatInt(a.GID, 10), "--", name}); e != nil {
		return false, e
	}
	_, e = n.run(ctx, "/usr/sbin/useradd", []string{"--uid", strconv.FormatInt(a.UID, 10), "--gid", strconv.FormatInt(a.GID, 10), "--no-create-home", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", "--no-log-init", "--", name})
	if e != nil {
		return true, e
	}
	_, e = n.account(ctx, a, false)
	return true, e
}
func (n *nativeRuntime) directory(in generated.LinuxRoleInput, d generated.LinuxRoleDirectory, create bool) (bool, error) {
	p := strings.TrimPrefix(DirectoryPath(in.RoleID, d.Selector), "/")
	if p == "" {
		return false, errNative
	}
	mode, e := strconv.ParseUint(d.Mode, 8, 32)
	if e != nil {
		return false, errNative
	}
	// Parents are administrator prepared and root owned; never recursively chown.
	if d.Selector == "work" {
		found := false
		for _, parent := range in.Directories {
			if parent.Selector == "state" {
				if _, e = n.directory(in, parent, false); e != nil {
					return false, e
				}
				found = true
			}
		}
		if !found {
			return false, errNative
		}
	} else if _, e = protectedInfo(n.root, path.Dir(p)); e != nil {
		return false, e
	}
	fs, e := os.OpenRoot(n.root)
	if e != nil {
		return false, e
	}
	defer fs.Close()
	st, e := fs.Lstat(p)
	if os.IsNotExist(e) && create && d.ExpectedState == "absent" {
		if e = fs.Mkdir(p, 0700); e != nil {
			return false, e
		}
		f, e := fs.OpenFile(p, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
		if e != nil {
			return true, e
		}
		defer f.Close()
		if e = f.Chown(int(d.UID), int(d.GID)); e != nil {
			return true, e
		}
		if e = f.Chmod(os.FileMode(mode)); e != nil {
			return true, e
		}
		return true, f.Sync()
	}
	if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || uint64(st.Mode().Perm()) != mode {
		return false, errNative
	}
	f, e := fs.OpenFile(p, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if e != nil {
		return false, e
	}
	defer f.Close()
	var u unix.Stat_t
	if unix.Fstat(int(f.Fd()), &u) != nil || int64(u.Uid) != d.UID || int64(u.Gid) != d.GID {
		return false, errNative
	}
	facts := directoryDigest(p, d.UID, d.GID, d.Mode)
	if d.ExpectedState != "absent" && d.ExpectedDigest != facts {
		return false, errNative
	}
	return false, nil
}
func directoryDigest(p string, uid, gid int64, mode string) string {
	return hostaction.Digest(map[string]any{"path": "/" + p, "uid": uid, "gid": gid, "mode": mode})
}
func (n *nativeRuntime) Apply(ctx context.Context, b generated.HostActionBundle, in generated.LinuxRoleInput) (RoleResult, error) {
	out := RoleResult{}
	e := n.withLock(ctx, func() (applyErr error) {
		if e := n.requireResolvedRoleJournal(); e != nil {
			return e
		}
		var rollbacks []roleUnitRollback
		bootLinkCreated := false
		defer func() {
			if applyErr != nil && bootLinkCreated {
				if e := n.removeRoleBootLink(UnitName(in.RoleID)); e != nil {
					applyErr = errNative
				}
			}
			if applyErr != nil {
				for i := len(rollbacks) - 1; i >= 0; i-- {
					if e := n.restoreRoleUnit(context.WithoutCancel(ctx), rollbacks[i]); e != nil {
						applyErr = errNative
					}
				}
			}
		}()
		if e := n.capacity(in); e != nil {
			return e
		}
		if e := n.unitOverrides(UnitName(in.RoleID)); e != nil {
			return e
		}
		if in.RoleID != "control" {
			if _, e := n.roleBootLink(UnitName(in.RoleID), false); e != nil && !os.IsNotExist(e) {
				return e
			}
		}
		files := DesiredFiles(in)
		names := []string{}
		for p := range files {
			names = append(names, p)
		}
		sort.Strings(names)
		// Verify every unit and tmpfiles preimage before accounts or paths change.
		for _, p := range names {
			old, e := readProtected(n.root, p, 65536)
			if e != nil && !os.IsNotExist(e) {
				return e
			}
			expected := in.ExpectedUnitDigest
			owned := ownedUnitPreimage(in, old)
			if p == TmpfilesPath(in.RoleID) {
				expected = in.ExpectedTmpfilesDigest
				owned = ownedTmpfilesPreimage(in, old)
			}
			if e == nil && !bytes.Equal(old, files[p]) && (expected == "" || hostaction.BytesDigest(old) != expected || !owned) {
				return errNative
			}
			if os.IsNotExist(e) && expected != "" {
				return errNative
			}
		}
		state, e := n.run(ctx, "/usr/bin/systemctl", []string{"show", UnitName(in.RoleID), "--property=ActiveState", "--value"})
		if e != nil {
			return e
		}
		active := strings.TrimSpace(string(state))
		if active != "inactive" && active != "active" {
			return errNative
		}
		if in.RoleID == "control" && active == "active" {
			if in.ExpectedServiceState != "active" {
				return errNative
			}
			for p, want := range files {
				got, e := readProtected(n.root, p, 65536)
				if e != nil || !bytes.Equal(got, want) {
					return errNative
				}
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
			_, e := n.resources(ctx, in)
			return e
		}
		for _, a := range in.Accounts {
			changed, e := n.account(ctx, a, true)
			out.Changed = out.Changed || changed
			if e != nil {
				return e
			}
		}
		for _, d := range in.Directories {
			changed, e := n.directory(in, d, true)
			out.Changed = out.Changed || changed
			if e != nil {
				return e
			}
		}
		for _, p := range names {
			old, e := readProtected(n.root, p, 65536)
			if e == nil && bytes.Equal(old, files[p]) {
				continue
			}
			if e != nil && !os.IsNotExist(e) {
				return e
			}
			// Preserve the exact old inert unit in a protected bounded journal. Account
			// and data directory creations are intentionally never undone.
			beforeMode := os.FileMode(0600)
			if e == nil {
				if st, se := protectedInfo(n.root, p); se == nil {
					beforeMode = st.Mode().Perm()
				} else {
					return se
				}
			}
			candidate := roleUnitRollback{Path: p, Before: old, BeforePresent: e == nil, BeforeMode: beforeMode, AfterDigest: hostaction.BytesDigest(files[p]), BundleDigest: hostaction.Digest(b), Status: "pending"}
			journal, _ := json.Marshal(append(append([]roleUnitRollback{}, rollbacks...), candidate))
			if e = writeProtected(n.root, "var/lib/vsk-labs/access-rollback/role-unit-before.json", journal); e != nil {
				return e
			}
			out.Changed = true
			rollbacks = append(rollbacks, candidate)
			if e = writeProtected(n.root, p, files[p]); e != nil {
				return e
			}
		}
		if out.Changed {
			if _, e = n.run(ctx, "/usr/bin/systemctl", []string{"daemon-reload"}); e != nil {
				return e
			}
		}
		if in.RoleID != "control" {
			if _, e = n.run(ctx, "/usr/bin/systemd-tmpfiles", []string{"--create", "/" + TmpfilesPath(in.RoleID)}); e != nil {
				return e
			}
			for _, d := range in.Directories {
				if d.Selector == "runtime" {
					if _, e = n.directory(in, d, false); e != nil {
						return e
					}
				}
			}
		}
		if in.RoleID != "control" {
			changed, e := n.roleBootLink(UnitName(in.RoleID), true)
			bootLinkCreated = changed
			out.Changed = out.Changed || changed
			if e != nil {
				return e
			}
			if changed {
				if _, e = n.run(ctx, "/usr/bin/systemctl", []string{"daemon-reload"}); e != nil {
					return e
				}
			}
		}
		if in.RoleID != "control" && active != "active" {
			out.Changed = true
			if _, e = n.run(ctx, "/usr/bin/systemctl", []string{"start", UnitName(in.RoleID)}); e != nil {
				return e
			}
		}
		return n.completeRoleJournal(rollbacks)
	})
	if e != nil {
		return out, e
	}
	col, e := n.Collect(ctx, b, in)
	out.Measurements = col.Measurements
	return out, e
}
func (n *nativeRuntime) freeSpace(in generated.LinuxRoleInput) error {
	var st unix.Statfs_t
	if unix.Statfs(path.Join(n.root, "var/lib/vsk-labs"), &st) != nil || st.Blocks == 0 {
		return errNative
	}
	free := st.Bavail * uint64(st.Bsize)
	if free < uint64(in.Resources.MinimumFreeBytes) || st.Bavail*100/st.Blocks < uint64(in.Resources.MinimumFreePercent) {
		return errNative
	}
	return nil
}
func resourceArgs(in generated.LinuxRoleInput) []string {
	return []string{"show", UnitName(in.RoleID), "--property=MemoryMax,CPUQuotaPerSecUSec,TasksMax,ActiveState,User,Group,MainPID,FragmentPath,ControlGroup,DropInPaths,UnitFileState", "--no-pager"}
}
func parseProperties(raw []byte) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			m[k] = v
		}
	}
	return m
}
func (n *nativeRuntime) resources(ctx context.Context, in generated.LinuxRoleInput) (map[string]string, error) {
	for p, want := range DesiredFiles(in) {
		got, e := readProtected(n.root, p, 65536)
		if e != nil || !bytes.Equal(got, want) {
			return nil, errNative
		}
	}
	raw, e := n.run(ctx, "/usr/bin/systemctl", resourceArgs(in))
	if e != nil {
		return nil, e
	}
	m := parseProperties(raw)
	if in.RoleID == "control" && (m["User"] != strconv.FormatInt(in.Accounts[0].UID, 10) || m["Group"] != strconv.FormatInt(in.Accounts[0].GID, 10)) {
		return m, errNative
	}
	expectedCPU := fmt.Sprintf("%dms", in.Resources.CPUQuotaPercent*10)
	if m["MemoryMax"] != strconv.FormatInt(in.Resources.MemoryMaxBytes, 10) || m["TasksMax"] != strconv.FormatInt(in.Resources.TasksMax, 10) || (m["CPUQuotaPerSecUSec"] != expectedCPU && m["CPUQuotaPerSecUSec"] != time.Duration(in.Resources.CPUQuotaPercent*10000000).String()) {
		return m, errNative
	}
	if m["UnitFileState"] != "enabled" {
		return m, errNative
	}
	if m["ActiveState"] != "active" || m["FragmentPath"] != "/etc/systemd/system/"+UnitName(in.RoleID) || m["DropInPaths"] != "" {
		return m, errNative
	}
	expectedGroup := "/vsk.slice/" + UnitName(in.RoleID)
	if in.RoleID == "control" {
		expectedGroup = "/system.slice/vsk-labs.service"
	}
	if m["ControlGroup"] != expectedGroup {
		return m, errNative
	}
	for file, expected := range map[string]string{"memory.max": strconv.FormatInt(in.Resources.MemoryMaxBytes, 10), "pids.max": strconv.FormatInt(in.Resources.TasksMax, 10)} {
		raw, e := os.ReadFile(path.Join(n.root, "sys/fs/cgroup", expectedGroup, file))
		if e != nil || len(raw) > 128 || strings.TrimSpace(string(raw)) != expected {
			return m, errNative
		}
		m[file] = strings.TrimSpace(string(raw))
	}
	raw, e = os.ReadFile(path.Join(n.root, "sys/fs/cgroup", expectedGroup, "cpu.max"))
	if e != nil || len(raw) > 128 {
		return m, errNative
	}
	cpu := strings.Fields(string(raw))
	if len(cpu) != 2 {
		return m, errNative
	}
	quota, e := strconv.ParseInt(cpu[0], 10, 64)
	period, e2 := strconv.ParseInt(cpu[1], 10, 64)
	if e != nil || e2 != nil || quota <= 0 || period <= 0 || quota*100 != period*in.Resources.CPUQuotaPercent {
		return m, errNative
	}
	m["cpu.max"] = strings.TrimSpace(string(raw))
	return m, n.freeSpace(in)
}

func (n *nativeRuntime) capacity(in generated.LinuxRoleInput) error {
	raw, e := os.ReadFile(path.Join(n.root, "proc/meminfo"))
	if e != nil || len(raw) > 65536 {
		return errNative
	}
	var memory int64
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) == 3 && f[0] == "MemTotal:" && f[2] == "kB" {
			memory, _ = strconv.ParseInt(f[1], 10, 64)
			memory *= 1024
		}
	}
	raw, e = os.ReadFile(path.Join(n.root, "proc/sys/kernel/threads-max"))
	if e != nil {
		return errNative
	}
	tasks, e := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if e != nil || memory <= 0 || tasks <= 0 {
		return errNative
	}
	r := in.Resources
	if r.MemoryMaxBytes > memory || r.CapacityMemoryBytes > memory || r.CPUQuotaPercent > int64(runtime.NumCPU()*100) || r.CapacityCPUPercent > int64(runtime.NumCPU()*100) || r.TasksMax > tasks || r.CapacityTasks > tasks {
		return errNative
	}
	return n.freeSpace(in)
}

func (n *nativeRuntime) unitOverrides(unit string) error {
	if unit != "vsk-labs.service" && unit != "vsk-application.slice" && unit != "vsk-ci.slice" && unit != "vsk-standby.slice" {
		return errNative
	}
	for _, base := range []string{"etc/systemd/system", "run/systemd/system", "usr/lib/systemd/system"} {
		p := path.Join(n.root, base, unit+".d")
		entries, e := os.ReadDir(p)
		if e == nil && len(entries) > 0 {
			return errNative
		}
		if e != nil && !os.IsNotExist(e) {
			return errNative
		}
		if st, e := os.Lstat(p); e == nil && st.Mode()&os.ModeSymlink != 0 {
			return errNative
		}
	}
	return nil
}

type roleUnitRollback struct {
	Path                              string
	Before                            []byte
	BeforePresent                     bool
	BeforeMode                        os.FileMode
	AfterDigest, BundleDigest, Status string
}

func (n *nativeRuntime) restoreRoleUnit(ctx context.Context, r roleUnitRollback) error {
	switch r.Path {
	case "etc/systemd/system/vsk-labs.service", "etc/systemd/system/vsk-application.slice", "etc/systemd/system/vsk-ci.slice", "etc/systemd/system/vsk-standby.slice", "etc/tmpfiles.d/vsk-application.conf", "etc/tmpfiles.d/vsk-ci.conf", "etc/tmpfiles.d/vsk-standby.conf":
	default:
		return errNative
	}
	current, e := readProtected(n.root, r.Path, 65536)
	if e != nil || hostaction.BytesDigest(current) != r.AfterDigest {
		return errNative
	}
	if r.BeforePresent {
		if e = writeProtected(n.root, r.Path, r.Before); e != nil {
			return e
		}
		fs, e := os.OpenRoot(n.root)
		if e != nil {
			return e
		}
		defer fs.Close()
		f, e := fs.OpenFile(r.Path, os.O_RDONLY|unix.O_NOFOLLOW, 0)
		if e != nil {
			return e
		}
		defer f.Close()
		if e = f.Chmod(r.BeforeMode); e != nil {
			return e
		}
		if e = f.Sync(); e != nil {
			return e
		}
	} else {
		fs, e := os.OpenRoot(n.root)
		if e != nil {
			return e
		}
		e = fs.Remove(r.Path)
		fs.Close()
		if e != nil {
			return e
		}
	}
	if _, e = n.run(ctx, "/usr/bin/systemctl", []string{"daemon-reload"}); e != nil {
		return e
	}
	r.Status = "restored"
	records := []roleUnitRollback{}
	if raw, re := readProtected(n.root, "var/lib/vsk-labs/access-rollback/role-unit-before.json", 65536); re == nil {
		if json.Unmarshal(raw, &records) != nil {
			return errNative
		}
	} else if !os.IsNotExist(re) {
		return re
	}
	found := false
	for i := range records {
		if records[i].Path == r.Path && records[i].AfterDigest == r.AfterDigest {
			records[i] = r
			found = true
		}
	}
	if !found {
		records = append(records, r)
	}
	raw, _ := json.Marshal(records)
	if e = writeProtected(n.root, "var/lib/vsk-labs/access-rollback/role-unit-before.json", raw); e != nil {
		return e
	}
	return nil
}
func ownedUnitPreimage(in generated.LinuxRoleInput, old []byte) bool {
	expected := regexp.QuoteMeta(string(DesiredFiles(in)["etc/systemd/system/"+UnitName(in.RoleID)]))
	for _, pair := range []struct {
		k string
		n int64
	}{{"MemoryMax", in.Resources.MemoryMaxBytes}, {"CPUQuota", in.Resources.CPUQuotaPercent}, {"TasksMax", in.Resources.TasksMax}} {
		expected = strings.Replace(expected, pair.k+"="+strconv.FormatInt(pair.n, 10), pair.k+"=[0-9]+", 1)
	}
	return regexp.MustCompile("^" + expected + "$").Match(old)
}

func ownedTmpfilesPreimage(in generated.LinuxRoleInput, old []byte) bool {
	expected := string(DesiredFiles(in)[TmpfilesPath(in.RoleID)])
	if expected == "" {
		return false
	}
	for _, d := range in.Directories {
		if d.Selector == "runtime" {
			pattern := regexp.QuoteMeta(expected)
			pattern = strings.Replace(pattern, " "+d.Mode+" ", " (0700|0750) ", 1)
			return regexp.MustCompile("^" + pattern + "$").Match(old)
		}
	}
	return false
}

const roleJournalPath = "var/lib/vsk-labs/access-rollback/role-unit-before.json"

func roleOwnedFile(p string) bool {
	switch p {
	case "etc/systemd/system/vsk-labs.service", "etc/systemd/system/vsk-application.slice", "etc/systemd/system/vsk-ci.slice", "etc/systemd/system/vsk-standby.slice", "etc/tmpfiles.d/vsk-application.conf", "etc/tmpfiles.d/vsk-ci.conf", "etc/tmpfiles.d/vsk-standby.conf":
		return true
	}
	return false
}
func (n *nativeRuntime) requireResolvedRoleJournal() error {
	raw, e := readProtected(n.root, roleJournalPath, 65536)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	var records []roleUnitRollback
	if json.Unmarshal(raw, &records) != nil || len(records) == 0 || len(records) > 2 {
		return errNative
	}
	seen := map[string]bool{}
	for _, r := range records {
		if !roleOwnedFile(r.Path) || seen[r.Path] || (r.Status != "completed" && r.Status != "restored") || r.AfterDigest == "" || r.BundleDigest == "" {
			return errNative
		}
		seen[r.Path] = true
	}
	return nil
}
func (n *nativeRuntime) completeRoleJournal(records []roleUnitRollback) error {
	if len(records) == 0 {
		return nil
	}
	if len(records) > 2 {
		return errNative
	}
	for i := range records {
		r := &records[i]
		got, e := readProtected(n.root, r.Path, 65536)
		if e != nil || hostaction.BytesDigest(got) != r.AfterDigest {
			return errNative
		}
		r.Status = "completed"
	}
	raw, e := json.Marshal(records)
	if e != nil {
		return e
	}
	return writeProtected(n.root, roleJournalPath, raw)
}

// Active control reapply only observes the approved executable/configuration.
// Its directories have already passed the exact role ownership checks.
func (n *nativeRuntime) activeControlFiles(in generated.LinuxRoleInput) error {
	executable, e := readProtected(n.root, "usr/local/bin/vsk-labs", 128<<20)
	if e != nil || hostaction.BytesDigest(executable) != in.ExecutableDigest {
		return errNative
	}
	fs, e := os.OpenRoot(n.root)
	if e != nil {
		return e
	}
	defer fs.Close()
	p := "etc/vsk-labs/control/server.json"
	f, e := fs.OpenFile(p, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if e != nil {
		return e
	}
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(int(f.Fd()), &st) != nil || int64(st.Uid) != in.Accounts[0].UID || st.Nlink != 1 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0022 != 0 || st.Size > 65536 {
		return errNative
	}
	raw, e := io.ReadAll(io.LimitReader(f, 65537))
	if e != nil || len(raw) > 65536 || hostaction.BytesDigest(raw) != in.ConfigDigest {
		return errNative
	}
	return nil
}
