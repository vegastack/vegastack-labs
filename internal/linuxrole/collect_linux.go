//go:build linux

package linuxrole

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/debianaccess"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"os"
	"path"
)

func (n *nativeRuntime) Collect(ctx context.Context, bundle generated.HostActionBundle, in generated.LinuxRoleInput) (RoleResult, error) {
	out := RoleResult{}
	for _, id := range in.ControlIDs {
		status, reason, verification := "partial", "role-observation-unavailable", "unavailable"
		var facts any = map[string]string{"control": id, "observation": "unavailable"}
		positive, negative := hostaction.BytesDigest(nil), hostaction.BytesDigest(nil)
		switch id {
		case "linux.role-identity-paths", "linux.role-workload-isolation":
			ok := true
			for _, a := range in.Accounts {
				if _, e := n.account(ctx, a, false); e != nil {
					ok = false
				}
			}
			for _, d := range in.Directories {
				if _, e := n.directory(in, d, false); e != nil {
					ok = false
				}
			}
			allow, deny, e := n.pathProbes(ctx, in)
			facts = map[string]any{"accounts": in.Accounts, "directories": in.Directories, "positive": allow, "negative": deny}
			positive = hostaction.Digest(allow)
			negative = hostaction.Digest(deny)
			if id == "linux.role-workload-isolation" {
				boundaries, be := n.workloadIsolation(ctx, in)
				facts = map[string]any{"paths": facts, "boundaries": boundaries}
				ok = ok && be == nil
			}
			if e == nil && ok {
				status = "passed"
				reason = "role-user-path-boundary-observed"
				verification = "effective-probe"
			} else {
				status = "failed"
				reason = "role-user-path-boundary-failed"
			}
		case "linux.role-service-resources":
			props, e := n.resources(ctx, in)
			facts = props
			if e == nil {
				status = "passed"
				reason = "role-resource-properties-observed"
				verification = "effective-probe"
			}
			if in.RoleID == "control" && props["ActiveState"] != "active" {
				status = "partial"
				reason = "control-service-pending-handoff"
			}
		case "linux.role-network-boundary":
			if in.NetworkAccess != nil {
				observed, e := debianaccess.NewNativeRuntime(n.version).Collect(ctx, bundle, *in.NetworkAccess)
				facts = observed.Measurements
				valid := e == nil
				found := false
				for _, m := range observed.Measurements {
					if m.ControlID == "debian.host-firewall" {
						found = true
						valid = valid && m.Status == "passed"
					}
				}
				if valid && found {
					status = "passed"
					reason = "role-network-policy-observed"
					verification = "configuration-observed"
				}
			}
			// Central receipt verification additionally requires current post-role #225
			// positive/negative probe and destination ownership proofs. Configuration
			// alone never satisfies admission.
			if bundle.ActionID == "debian.role.apply" {
				status = "partial"
				reason = "access-probe-recollection-required"
			}
		case "linux.control-service":
			observedInput := in
			if in.Handoff == nil {
				if receipt, e := n.readHandoff(); e == nil && receipt.Status == "completed" && receipt.Input.HostID == in.HostID && receipt.Input.RoleBindingDigest == in.RoleBindingDigest {
					observedInput = receipt.Input
				}
			}
			state, e := n.handoffState(ctx, observedInput)
			facts = state
			if e == nil && state.ServiceActive && ValidateControlHandoff(observedInput, state) == nil {
				status = "passed"
				reason = "same-database-control-service-observed"
				verification = "effective-probe"
			} else {
				reason = "control-service-handoff-unverified"
			}
		case "linux.reserve-no-workloads":
			observed, e := n.reserveAbsence(ctx, in)
			facts = observed
			if e == nil {
				status = "passed"
				reason = "managed-role-workloads-credentials-absent"
				verification = "effective-probe"
			}

		}
		m := generated.AccessMeasurement{Schema: generated.SchemaIDAccessMeasurement, SchemaVersion: "1.0.0", ControlID: id, Kind: "role", Status: status, Reason: reason, SubjectHostID: in.HostID, SubjectIdentityDigest: in.HostIdentityDigest, ProfileLockDigest: in.ProfileLockDigest, ProducerID: "linux-role", ProducerVersion: "1.0.0", ObservedAt: n.now().UTC().Format(time.RFC3339), ConfigurationDigest: hostaction.Digest(in), PositiveProbeDigest: positive, NegativeProbeDigest: negative, Role: &generated.RoleObservation{Schema: generated.SchemaIDRoleObservation, SchemaVersion: "1.0.0", RoleID: in.RoleID, RoleBindingDigest: in.RoleBindingDigest, FactsDigest: hostaction.Digest(facts), Verification: verification}}
		out.Measurements = append(out.Measurements, m)
	}
	return out, nil
}
func (n *nativeRuntime) pathProbes(ctx context.Context, in generated.LinuxRoleInput) ([]string, []string, error) {
	var allowed, denied []string
	// A real distinct unprivileged OS identity must exist before negative probes.
	raw, e := n.run(ctx, "/usr/bin/getent", []string{"passwd", "65534"})
	if e != nil {
		return nil, nil, e
	}
	fields := strings.Split(strings.TrimSpace(string(raw)), ":")
	if len(fields) != 7 || fields[2] != "65534" {
		return nil, nil, errNative
	}
	gid := fields[3]
	for _, d := range in.Directories {
		if d.UID == 65534 {
			return nil, nil, errNative
		}
		p := "/" + strings.TrimPrefix(DirectoryPath(in.RoleID, d.Selector), "/")
		args := []string{"--reuid", strconv.FormatInt(d.UID, 10), "--regid", strconv.FormatInt(d.GID, 10), "--clear-groups", "--bounding-set=-all", "--no-new-privs", "/usr/bin/test", "-r", p}
		if _, e = n.run(ctx, "/usr/bin/setpriv", args); e != nil {
			return allowed, denied, e
		}
		allowed = append(allowed, p)
		args = []string{"--reuid", "65534", "--regid", gid, "--clear-groups", "--bounding-set=-all", "--no-new-privs", "/usr/bin/test", "!", "-r", p}
		if _, e = n.run(ctx, "/usr/bin/setpriv", args); e != nil {
			return allowed, denied, e
		}
		denied = append(denied, p)
	}
	if len(allowed) == 0 || len(allowed) != len(denied) {
		return allowed, denied, errNative
	}
	return allowed, denied, nil
}

func (n *nativeRuntime) reserveAbsence(ctx context.Context, in generated.LinuxRoleInput) (map[string]any, error) {
	facts := map[string]any{}
	for _, args := range [][]string{{"list-units", "--all", "--type=service", "--plain", "--no-legend", "--no-pager"}, {"list-unit-files", "--type=service", "--no-legend", "--no-pager"}} {
		raw, e := n.run(ctx, "/usr/bin/systemctl", args)
		if e != nil || len(raw) > 65536 {
			return facts, errNative
		}
		facts[args[0]] = hostaction.BytesDigest(raw)
		for _, line := range strings.Split(string(raw), "\n") {
			f := strings.Fields(line)
			if len(f) == 0 {
				continue
			}
			unit := strings.ToLower(f[0])
			for _, forbidden := range []string{"vsk-workload", "vsk-job", "actions.runner", "gitlab-runner", "coolify", "harbor", "docker", "containerd", "kubelet", "podman"} {
				if strings.Contains(unit, forbidden) {
					return facts, errNative
				}
			}
		}
	}
	for _, d := range in.Directories {
		p := DirectoryPath(in.RoleID, d.Selector)
		if _, e := n.directory(in, d, false); e != nil {
			return facts, e
		}
		entries, e := os.ReadDir(path.Join(n.root, p))
		if e != nil || len(entries) != 0 {
			return facts, errNative
		}
		facts[d.Selector] = "observed-empty"
	}
	return facts, nil
}
