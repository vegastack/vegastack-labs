//go:build linux || darwin

package debianaccess

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ArmBaseline uses the existing finite rollback record and timer. Every file and
// service is checked against a closed baseline-only allowlist before access.
func ArmBaseline(ctx context.Context, b generated.HostActionBundle, files map[string][]byte, services []string) (string, error) {
	n := &nativeRuntime{root: "/", run: nativeCommand, now: func() time.Time { return time.Now().UTC() }}
	return n.armBaseline(ctx, b, files, services)
}
func (n *nativeRuntime) armBaseline(ctx context.Context, b generated.HostActionBundle, files map[string][]byte, services []string) (string, error) {
	if len(files) == 0 || len(files) > 5 || !validBaselineServices(services) {
		return "", errAccess
	}
	boot, e := os.ReadFile(n.root + "/proc/sys/kernel/random/boot_id")
	if e != nil {
		return "", e
	}
	bd, e := hostaction.BundleDigest(b)
	if e != nil {
		return "", e
	}
	armedAt := n.now()
	r := RollbackRecord{HostID: b.HostID, HostIdentityDigest: b.HostIdentityDigest, PlanID: b.PlanID, RunID: b.RunID, InputDigest: b.ActionInputDigest, AuthorizationDigest: b.PlanDigest, BundleDigest: bd, BootID: strings.TrimSpace(string(boot)), ArmedAt: armedAt, Deadline: armedAt.Add(600 * time.Second), State: "armed", BaselineServices: services}
	r.BaselineServiceStates = map[string]string{}
	for _, service := range services {
		if service == "apparmor.service" {
			return "", errAccess
		}
		raw, e := n.run(ctx, "/usr/bin/systemctl", []string{"show", service, "--property=ActiveState", "--value"}, nil)
		if e != nil {
			return "", e
		}
		state := strings.TrimSpace(string(raw))
		if state != "active" && state != "inactive" {
			return "", errAccess
		}
		r.BaselineServiceStates[service] = state
	}
	for _, service := range services {
		if service == "auditd.service" {
			raw, e := n.run(ctx, "/usr/sbin/auditctl", []string{"-s"}, nil)
			if e != nil {
				return "", e
			}
			values := map[string]int64{}
			for _, line := range strings.Split(string(raw), "\n") {
				f := strings.Fields(line)
				if len(f) == 2 {
					v, e := strconv.ParseInt(f[1], 10, 64)
					if e == nil {
						values[f[0]] = v
					}
				}
			}
			if values["enabled"] != 1 || values["backlog_limit"] <= 0 || values["rate_limit"] < 0 || values["failure"] < 0 || values["failure"] > 1 {
				return "", errAccess
			}
			r.BaselineAudit = &BaselineAuditState{RateLimit: values["rate_limit"], BacklogLimit: values["backlog_limit"], FailureMode: values["failure"]}
		}
	}
	fs, e := os.OpenRoot(n.root)
	if e != nil {
		return "", e
	}
	defer fs.Close()
	names := []string{}
	for p := range files {
		names = append(names, p)
	}
	sort.Strings(names)
	for _, p := range names {
		if !baselineOwnedFile(p) {
			return "", errAccess
		}
		raw, mode, e := readProtected(fs, p)
		if e != nil && !os.IsNotExist(e) {
			return "", e
		}
		r.Files = append(r.Files, RollbackFile{Path: p, Before: raw, BeforePresent: e == nil, BeforeMode: mode, AfterDigest: digestBytes(files[p]), AfterMode: 0600})
	}
	if e = Arm(ctx, n.root, r); e != nil {
		return "", e
	}
	if e = n.armTimer(ctx, r); e != nil {
		return "", e
	}
	return r.Digest(), nil
}

// ConfirmBaseline can close only a baseline record after exact desired files exist.
func ConfirmBaseline(ctx context.Context, digest, evidence string) error {
	return withRollback(ctx, "/", func(fs *os.Root) error {
		r, e := readRollback(fs)
		if e != nil || r.Digest() != digest || len(r.BaselineServices) == 0 || r.State != "armed" || !time.Now().Before(r.Deadline) {
			return errAccess
		}
		for _, f := range r.Files {
			raw, mode, e := readProtected(fs, f.Path)
			if e != nil || digestBytes(raw) != f.AfterDigest || mode != f.AfterMode {
				return errAccess
			}
		}
		r.State = "confirmed"
		r.ProbeDigest = evidence
		if e = saveRollback(fs, r); e != nil {
			return e
		}
		_, e = nativeCommand(ctx, "/usr/bin/systemctl", []string{"stop", "vsk-access-rollback.timer"}, nil)
		return e
	})
}

// WriteBaseline holds the same lock as timer restoration and refuses changed
// preimages. It accepts only the exact already-armed baseline file map.
func WriteBaseline(ctx context.Context, digest string, files map[string][]byte) (bool, error) {
	return writeBaseline(ctx, "/", digest, files)
}
func writeBaseline(ctx context.Context, root, digest string, files map[string][]byte) (bool, error) {
	changed := false
	e := withRollback(ctx, root, func(fs *os.Root) error {
		r, e := readRollback(fs)
		if e != nil || r.Digest() != digest || r.State != "armed" || len(r.BaselineServices) == 0 || len(files) != len(r.Files) || !time.Now().Before(r.Deadline) {
			return errAccess
		}
		for _, f := range r.Files {
			b, ok := files[f.Path]
			if !ok || digestBytes(b) != f.AfterDigest {
				return errAccess
			}
			old, mode, e := readProtected(fs, f.Path)
			if f.BeforePresent {
				if e != nil || digestBytes(old) != digestBytes(f.Before) || mode != f.BeforeMode {
					return errAccess
				}
			} else if !os.IsNotExist(e) {
				return errAccess
			}
		}
		for _, f := range r.Files {
			if e := ctx.Err(); e != nil {
				return e
			}
			if e := writeAtomic(fs, f.Path, files[f.Path], 0600); e != nil {
				return e
			}
			changed = true
		}
		return nil
	})
	return changed, e
}
