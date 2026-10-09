//go:build linux || darwin

package debianaccess

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"os"
	"path"
	"strings"
	"time"
)

func ArmBaselineProfiles(ctx context.Context, b generated.HostActionBundle, files map[string][]byte, services []string, profiles []BaselineProfile) (string, error) {
	n := &nativeRuntime{root: "/", run: nativeCommand, now: time.Now}
	return n.armBaselineProfiles(ctx, b, files, services, profiles)
}
func (n *nativeRuntime) checkBaselineProfiles(ctx context.Context, profiles []BaselineProfile, absent bool) error {
	if len(profiles) == 0 {
		return nil
	}
	raw, e := n.run(ctx, "/usr/sbin/aa-status", []string{"--json"}, nil)
	if e != nil {
		return e
	}
	var status struct {
		Profiles map[string]string `json:"profiles"`
	}
	if json.Unmarshal(raw, &status) != nil || status.Profiles == nil {
		return errAccess
	}
	fs, e := os.OpenRoot(n.root)
	if e != nil {
		return e
	}
	defer fs.Close()
	for _, p := range profiles {
		if !validBaselineProfile(p) {
			return errAccess
		}
		data, _, e := readProtected(fs, p.File)
		if e != nil || digestBytes(data) != p.Digest {
			return errAccess
		}
		// Includes can change independently of the file digest; this recoverable
		// loading case accepts a self-contained single profile only.
		if strings.Contains(string(data), "include") {
			return errAccess
		}
		names, e := n.run(ctx, "/usr/sbin/apparmor_parser", []string{"--names", "--skip-cache", "--config-file=/dev/null", "--", path.Join(n.root, p.File)}, nil)
		if e != nil || strings.TrimSpace(string(names)) != p.Name {
			return errAccess
		}
		mode, exists := status.Profiles[p.Name]
		if absent && exists {
			return errAccess
		}
		if !absent && exists && mode != "enforce" {
			return errAccess
		}
	}
	return nil
}
func LoadBaselineProfiles(ctx context.Context, digest string) error {
	n := &nativeRuntime{root: "/", run: nativeCommand, now: time.Now}
	return n.loadBaselineProfiles(ctx, digest)
}
func (n *nativeRuntime) loadBaselineProfiles(ctx context.Context, digest string) error {
	return withRollback(ctx, n.root, func(fs *os.Root) error {
		r, e := readRollback(fs)
		if e != nil || r.Digest() != digest || r.State != "armed" || !n.now().Before(r.Deadline) {
			return errAccess
		}
		if e = n.checkBaselineProfiles(ctx, r.BaselineProfiles, true); e != nil {
			return e
		}
		if r.BaselineProfileStates == nil {
			r.BaselineProfileStates = map[string]string{}
		}
		for _, p := range r.BaselineProfiles {
			if r.BaselineProfileStates[p.Name] != "" {
				return errAccess
			}
		}
		for _, p := range r.BaselineProfiles {
			r.BaselineProfileStates[p.Name] = "adding"
			if e = saveRollback(fs, r); e != nil {
				return e
			}
			if _, e = n.run(ctx, "/usr/sbin/apparmor_parser", []string{"--add", "--skip-cache", "--config-file=/dev/null", "--", path.Join(n.root, p.File)}, nil); e != nil {
				return e
			}
			r.BaselineProfileStates[p.Name] = "added"
			if e = saveRollback(fs, r); e != nil {
				return e
			}
		}
		return nil
	})
}
func (n *nativeRuntime) restoreBaselineProfiles(ctx context.Context, r RollbackRecord, newBoot bool) error {
	profiles := r.BaselineProfiles
	if e := n.checkBaselineProfiles(ctx, profiles, false); e != nil {
		return e
	}
	ambiguous := false
	for _, p := range profiles {
		raw, e := n.run(ctx, "/usr/sbin/aa-status", []string{"--json"}, nil)
		if e != nil {
			return e
		}
		var s struct {
			Profiles map[string]string `json:"profiles"`
		}
		if json.Unmarshal(raw, &s) != nil {
			return errAccess
		}
		state := r.BaselineProfileStates[p.Name]
		if state == "adding" {
			ambiguous = true
			continue
		}
		if _, ok := s.Profiles[p.Name]; !ok {
			continue
		}
		if state != "added" || newBoot {
			ambiguous = true
			continue
		}
		if _, e = n.run(ctx, "/usr/sbin/apparmor_parser", []string{"--remove", "--skip-cache", "--config-file=/dev/null", "--", path.Join(n.root, p.File)}, nil); e != nil {
			return e
		}
	}
	if ambiguous {
		return errAccess
	}
	return nil
}
