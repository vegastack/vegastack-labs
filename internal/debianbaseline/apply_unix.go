//go:build linux || darwin

package debianbaseline

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/debianaccess"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"os"
	"path"
	"strings"
	"syscall"
)

func (n *nativeRuntime) Apply(ctx context.Context, b generated.HostActionBundle, in generated.DebianBaselineInput) (Result, error) {
	if e := n.Inspect(ctx, b, in); e != nil {
		return Result{}, e
	}
	if b.ActionID == "debian.aide.initialize" || b.ActionID == "debian.aide.refresh" {
		return n.applyAIDE(ctx, b, in)
	}
	files := DesiredFiles(in)
	services := []string{}
	if selected(in, "linux.fail2ban-sshd") {
		services = append(services, "fail2ban.service")
	}
	if selected(in, "linux.audit-bounded") {
		services = append(services, "auditd.service")
	}

	// Health and storage selectors never silently mutate OS settings.
	if len(files) == 0 {
		if selected(in, "linux.apparmor-enforcing") {
			changed, e := n.loadProfiles(ctx, in)
			if e != nil {
				return Result{Changed: changed}, e
			}
			m, e := Collect(ctx, in, n)
			return Result{Changed: changed, Measurements: m}, e
		}
		return n.Collect(ctx, b, in)
	}
	if len(services) == 0 {
		return Result{}, errBaseline
	}
	// All target files and ancestors must already be installed by the bounded
	// administrator preparation or packaged OS; no arbitrary directory creation.
	for p := range files {
		if _, e := protectedRead(n.root, p, 65536); e != nil && !os.IsNotExist(e) {
			return Result{}, e
		}
	}
	if selected(in, "linux.fail2ban-sshd") {
		for family, bin := range map[string]string{"ipv4": "/usr/sbin/iptables-nft", "ipv6": "/usr/sbin/ip6tables-nft"} {
			raw, e := n.run(ctx, bin, []string{"-w", "5", "-S"}, nil)
			if e != nil {
				return Result{}, e
			}
			if strings.Contains(string(raw), "f2b-vsk-sshd") && !debianaccess.ValidateSSHBanPrefix(string(raw), family) {
				return Result{}, errBaseline
			}
		}
	}
	digest, e := debianaccess.ArmBaseline(ctx, b, files, services)
	if e != nil {
		return Result{}, e
	}
	changed, e := debianaccess.WriteBaseline(ctx, digest, files)
	if e != nil {
		return Result{Changed: changed}, e
	}

	if selected(in, "linux.fail2ban-sshd") {
		if _, e = n.run(ctx, "/usr/bin/fail2ban-client", []string{"-t"}, nil); e != nil {
			return Result{Changed: true}, e
		}
		if _, e = n.run(ctx, "/usr/bin/systemctl", []string{"is-active", "fail2ban.service"}, nil); e != nil {
			if _, e = n.run(ctx, "/usr/bin/systemctl", []string{"start", "fail2ban.service"}, nil); e != nil {
				return Result{Changed: true}, e
			}
		}
		if _, e = n.run(ctx, "/usr/bin/fail2ban-client", []string{"reload", "sshd"}, nil); e != nil {
			return Result{Changed: true}, e
		}
	}
	if selected(in, "linux.audit-bounded") {
		if _, e = n.run(ctx, "/usr/bin/systemctl", []string{"start", "auditd.service"}, nil); e != nil {
			return Result{Changed: true}, e
		}
		if _, e = n.run(ctx, "/usr/sbin/auditctl", []string{"-D", "-k", "vsk-security"}, nil); e != nil {
			return Result{Changed: true}, e
		}
		if _, e = n.run(ctx, "/usr/sbin/auditctl", []string{"-R", "/etc/audit/rules.d/70-vsk-security.rules"}, nil); e != nil {
			return Result{Changed: true}, e
		}
		if _, e = n.run(ctx, "/usr/bin/systemctl", []string{"reload", "auditd.service"}, nil); e != nil {
			return Result{Changed: true}, e
		}
	}
	if selected(in, "linux.apparmor-enforcing") {
		did, e := n.loadProfiles(ctx, in)
		changed = changed || did
		if e != nil {
			return Result{Changed: changed}, e
		}
	}

	m, e := Collect(ctx, in, n)
	out := Result{Changed: changed, Measurements: m}
	if e != nil {
		return out, e
	}
	for _, v := range m {
		if v.Status != "passed" {
			return out, errBaseline
		}
	}
	if e = debianaccess.ConfirmBaseline(ctx, digest, hostaction.Digest(m)); e != nil {
		return out, e
	}
	return out, nil
}
func protectedWrite(root, p string, b []byte) error {
	if path.IsAbs(p) || path.Clean(p) != p || strings.HasPrefix(p, "../") {
		return errBaseline
	}
	fs, e := os.OpenRoot(root)
	if e != nil {
		return e
	}
	defer fs.Close()
	// OpenRoot prevents escapes; each existing ancestor additionally denies links
	// and writable policy directories before the atomic write.
	parts := strings.Split(path.Dir(p), "/")
	for i := range parts {
		st, e := fs.Lstat(strings.Join(parts[:i+1], "/"))
		if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0022 != 0 {
			return errBaseline
		}
		stat, ok := st.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(os.Geteuid()) {
			return errBaseline
		}
	}
	if st, e := fs.Lstat(p); e == nil {
		stat, ok := st.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || !st.Mode().IsRegular() || st.Mode().Perm()&0022 != 0 {
			return errBaseline
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	tmp := p + ".vsk-new"
	f, e := fs.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	defer fs.Remove(tmp)
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
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
func (n *nativeRuntime) applyAIDE(ctx context.Context, b generated.HostActionBundle, in generated.DebianBaselineInput) (Result, error) {
	if in.RoleID != "control" || !selected(in, "linux.aide-integrity") {
		return Result{}, errBaseline
	}
	p := "var/lib/vsk-labs/baseline/aide.db"
	old, e := protectedRead(n.root, p, 16<<20)
	if b.ActionID == "debian.aide.initialize" {
		if !os.IsNotExist(e) {
			return Result{}, errBaseline
		}
	} else {
		if e != nil || digestBytes(old) != in.AIDE.PreviousDigest || in.AIDE.ApprovedChangeDigest == "" {
			return Result{}, errBaseline
		}
	}
	cfg := DesiredFiles(in)["etc/vsk-labs/baseline/aide.conf"]
	if len(cfg) == 0 {
		return Result{}, errBaseline
	}
	reviewed := map[string]string{}
	for _, name := range in.AIDE.ScopePaths {
		raw, e := protectedRead(n.root, strings.TrimPrefix(name, "/"), 16<<20)
		if e != nil {
			return Result{}, e
		}
		reviewed[name] = digestBytes(raw)
	}
	if in.AIDE.ApprovedChangeDigest == "" || hostaction.Digest(reviewed) != in.AIDE.ApprovedChangeDigest {
		return Result{}, errBaseline
	}
	if _, e := os.Lstat(path.Join(n.root, "var/lib/vsk-labs/baseline/aide.new.db")); !os.IsNotExist(e) {
		return Result{}, errBaseline
	}
	if e = protectedWrite(n.root, "etc/vsk-labs/baseline/aide.conf", cfg); e != nil {
		return Result{}, e
	}
	if _, e = n.run(ctx, "/usr/bin/aide", []string{"--init", "--config=/etc/vsk-labs/baseline/aide.conf"}, nil); e != nil {
		return Result{Changed: true}, e
	}
	fresh, e := protectedRead(n.root, "var/lib/vsk-labs/baseline/aide.new.db", 16<<20)
	if e != nil {
		return Result{Changed: true}, e
	}
	reference := aideReference{ScopeDigest: in.AIDE.ScopeDigest, DatabaseDigest: digestBytes(fresh), ApprovedChangeDigest: in.AIDE.ApprovedChangeDigest}
	raw, _ := json.Marshal(reference)
	// Database first, reference last: interruption is a visible mismatch, never
	// accepted as a refreshed reference. Existing DB is replaced only on refresh.
	current, currentErr := protectedRead(n.root, p, 16<<20)
	if b.ActionID == "debian.aide.initialize" {
		if !os.IsNotExist(currentErr) {
			return Result{Changed: true}, errBaseline
		}
	} else if currentErr != nil || digestBytes(current) != in.AIDE.PreviousDigest {
		return Result{Changed: true}, errBaseline
	}
	if e = protectedWrite(n.root, p, fresh); e != nil {
		return Result{Changed: true}, e
	}
	if e = protectedWrite(n.root, "var/lib/vsk-labs/baseline/aide-reference.json", raw); e != nil {
		return Result{Changed: true}, e
	}
	if e = os.Remove(path.Join(n.root, "var/lib/vsk-labs/baseline/aide.new.db")); e != nil {
		return Result{Changed: true}, e
	}
	originalDigest := hostaction.Digest(in)
	in.AIDE.ReferenceDigest = reference.DatabaseDigest
	m, e := Collect(ctx, in, n)
	for i := range m {
		m[i].ConfigurationDigest = originalDigest
		if m[i].ControlID == "linux.aide-integrity" {
			m[i].Baseline.AIDEReferenceDigest = reference.DatabaseDigest
		}
	}
	return Result{Changed: true, Measurements: m}, e
}

func (n *nativeRuntime) loadProfiles(ctx context.Context, in generated.DebianBaselineInput) (bool, error) {
	changed := false
	for _, p := range in.AppArmorProfiles {
		integrity, e := n.Read(ctx, ReadRequest{Operation: ReadPackageIntegrity, Selector: p.PackageName})
		if e != nil || len(strings.TrimSpace(string(integrity))) != 0 {
			return changed, errBaseline
		}

		raw, e := n.Read(ctx, ReadRequest{Operation: ReadProfile, Selector: p.ProfileID})
		if e != nil || digestBytes(raw) != p.ProfileDigest || strings.Contains(string(raw), "complain") {
			return changed, errBaseline
		}
		if _, e = n.run(ctx, "/usr/sbin/apparmor_parser", []string{"--replace", "--", path.Join(n.root, "etc/apparmor.d", p.ProfileID)}, nil); e != nil {
			return changed, e
		}
		changed = true
	}
	return changed, nil
}
