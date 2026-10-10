//go:build linux

package debianaccess

import (
	"context"
	"encoding/json"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func ObserveNativeRollback(ctx context.Context, expectedRecordDigest string) (NativeRollbackObservation, error) {
	if os.Geteuid() != 0 {
		return NativeRollbackObservation{}, errAccess
	}
	n := &nativeRuntime{root: "/", run: nativeCommand, now: func() time.Time { return time.Now().UTC() }}
	return n.observeNativeRollback(ctx, expectedRecordDigest)
}
func (n *nativeRuntime) observeNativeRollback(ctx context.Context, expected string) (NativeRollbackObservation, error) {
	var out NativeRollbackObservation
	if ctx == nil || ctx.Err() != nil || !digestRE.MatchString(expected) {
		return out, errAccess
	}
	root, err := os.OpenRoot(n.root)
	if err != nil {
		return out, err
	}
	defer root.Close()
	if err = checkProtected(root, rollbackDirectory+"/lock", false); err != nil {
		return out, err
	}
	lock, err := root.OpenFile(rollbackDirectory+"/lock", os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return out, err
	}
	defer lock.Close()
	if unix.Flock(int(lock.Fd()), unix.LOCK_SH|unix.LOCK_NB) != nil {
		return out, errAccess
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	record, err := readRollback(root)
	if err != nil || record.Digest() != expected || record.RunID == "" || len(record.BaselineServices) != 0 || len(record.BaselineProfiles) != 0 || record.BaselineAudit != nil {
		return out, errAccess
	}
	type fileState struct {
		Path    string
		Present bool
		Mode    os.FileMode
		Digest  string
	}
	type aggregate struct {
		Files    []fileState
		Firewall []FirewallState
	}
	before := aggregate{[]fileState{}, []FirewallState{}}
	applied := aggregate{[]fileState{}, []FirewallState{}}
	current := aggregate{[]fileState{}, []FirewallState{}}
	for _, file := range record.Files {
		before.Files = append(before.Files, fileState{file.Path, file.BeforePresent, file.BeforeMode, digestBytes(file.Before)})
		applied.Files = append(applied.Files, fileState{file.Path, true, file.AfterMode, file.AfterDigest})
		raw, mode, e := readProtected(root, file.Path)
		present := true
		if os.IsNotExist(e) {
			present = false
			mode = 0
			raw = nil
		} else if e != nil {
			return out, e
		}
		current.Files = append(current.Files, fileState{file.Path, present, mode, digestBytes(raw)})
	}
	for _, firewall := range record.Firewall {
		observed, e := n.inspectChain(ctx, firewall.Family, firewall.Chain)
		if e != nil {
			return out, e
		}
		before.Firewall = append(before.Firewall, firewall.Before)
		applied.Firewall = append(applied.Firewall, firewall.After)
		current.Firewall = append(current.Firewall, observed)
	}
	hash := func(v any) string { raw, _ := json.Marshal(v); return digestBytes(raw) }
	boot, err := os.ReadFile(filepath.Join(n.root, "proc/sys/kernel/random/boot_id"))
	if err != nil || len(boot) > 128 {
		return out, errAccess
	}
	bootID := strings.TrimSpace(string(boot))
	if bootID == "" {
		return out, errAccess
	}
	out = NativeRollbackObservation{RecordDigest: record.Digest(), RunID: record.RunID, HostID: record.HostID, HostIdentityDigest: record.HostIdentityDigest, PlanID: record.PlanID, InputDigest: record.InputDigest, AuthorizationDigest: record.AuthorizationDigest, BundleDigest: record.BundleDigest, State: record.State, ArmedAt: record.ArmedAt.UTC().Format(time.RFC3339Nano), Deadline: record.Deadline.UTC().Format(time.RFC3339Nano), ObservedAt: n.now().UTC().Format(time.RFC3339Nano), ArmedBootID: record.BootID, ReconciledBootID: record.ReconciledBootID, CurrentBootID: bootID, BeforeOwnedDigest: hash(before), AppliedOwnedDigest: hash(applied), CurrentOwnedDigest: hash(current), FileCount: len(record.Files), FirewallCount: len(record.Firewall)}
	return out, nil
}
