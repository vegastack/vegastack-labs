//go:build linux || darwin

package debianaccess

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/ssh"
	"os"
	"path"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

type nativeRuntime struct {
	revokeSessions    func(context.Context, int64) (bool, error)
	executableVersion string
	readContexts      func() ([]PreparedProbeContext, error)
	observeContainer  func(context.Context, PreparedProbeContext) ([]generated.AccessDestinationObservation, error)
	interfaces        func() ([]interfaceFact, error)
	homeOwnership     func(*os.File) (uint32, uint32, error)
	root              string
	run               commandRunner
	now               func() time.Time
	armed             *RollbackRecord
	input             *generated.DebianAccessInput
}

func NewNativeRuntime(version string) Runtime {
	return &nativeRuntime{executableVersion: version, revokeSessions: revokeManagedAutomationSessions, root: "/", run: nativeCommand, now: func() time.Time { return time.Now().UTC() }}
}
func (n *nativeRuntime) read(p string) ([]byte, error) {
	r, e := os.OpenRoot(n.root)
	if e != nil {
		return nil, e
	}
	defer r.Close()
	b, _, e := readProtected(r, p)
	return b, e
}
func (n *nativeRuntime) Inspect(ctx context.Context, b generated.HostActionBundle, in generated.DebianAccessInput) (RollbackRecord, error) {
	var record RollbackRecord
	if err := n.inspectProfile(ctx, in); err != nil {
		return record, err
	}
	if err := n.inspectAccounts(in); err != nil {
		return record, err
	}
	if err := n.inspectSudo(ctx, in); err != nil {
		return record, err
	}
	if err := n.inspectInterfaces(in); err != nil {
		return record, err
	}
	if err := n.inspectExistingKeys(in); err != nil {
		return record, err
	}
	if err := n.inspectSSH(ctx, in); err != nil {
		return record, err
	}
	boot, err := os.ReadFile(path.Join(n.root, "proc/sys/kernel/random/boot_id"))
	if err != nil || len(boot) > 128 {
		return record, errAccess
	}
	now := n.now()
	bd, err := hostaction.BundleDigest(b)
	if err != nil {
		return record, err
	}
	record = RollbackRecord{HostID: in.HostID, HostIdentityDigest: in.HostIdentityDigest, PlanID: b.PlanID, RunID: b.RunID, InputDigest: b.ActionInputDigest, AuthorizationDigest: in.RollbackDigest, BundleDigest: bd, BootID: strings.TrimSpace(string(boot)), ArmedAt: now, Deadline: now.Add(600 * time.Second), State: "armed"}
	if in.RevokeAutomationSessionsRetainedPublicKey != "" {
		record.AutomationUID = in.AutomationUID
		record.RevokeAutomationSessionsRetainedPublicKey = in.RevokeAutomationSessionsRetainedPublicKey
		for _, account := range in.Accounts {
			if account.Role == "automation" {
				record.AutomationAccount = account.Name
			}
		}
	}
	desired, err := DesiredFiles(in)
	if err != nil {
		return record, err
	}
	fs, err := os.OpenRoot(n.root)
	if err != nil {
		return record, err
	}
	defer fs.Close()
	ids := map[string]generated.AccessOwnedState{}
	for _, s := range in.RollbackSpecification.OwnedState {
		ids[s.ResourceID] = s
	}
	paths := make([]string, 0, len(desired))
	for p := range desired {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		before, mode, e := readProtected(fs, p)
		present := e == nil
		if e != nil && !os.IsNotExist(e) {
			return record, e
		}
		if !present {
			mode = 0600
			if e = checkProtected(fs, path.Dir(p), true); e != nil {
				return record, e
			}
		}
		spec, ok := ids[resourceForFile(p)]
		if !ok || spec.BeforeDigest != digestBytes(before) || spec.AfterDigest != digestBytes(desired[p]) {
			return record, errAccess
		}
		delete(ids, resourceForFile(p))
		record.Files = append(record.Files, RollbackFile{Path: p, Before: before, BeforePresent: present, BeforeMode: mode, AfterMode: desiredFileMode(p), AfterDigest: digestBytes(desired[p])})
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		for _, chain := range []string{"VSK-ACCESS-IN", "VSK-ACCESS-DKR"} {
			rules, e := DesiredFirewallRules(in, family, chain)
			if e != nil {
				return record, e
			}
			before, e := n.inspectChain(ctx, family, chain)
			if e != nil {
				return record, e
			}
			if !before.ParentPresent {
				if chain != "VSK-ACCESS-DKR" {
					return record, errAccess
				}
				if _, e = n.run(ctx, "/usr/bin/systemctl", []string{"is-active", "docker.service"}, nil); e == nil {
					return record, errAccess
				}
				if _, e = os.Lstat(path.Join(n.root, "var/run/docker.sock")); !os.IsNotExist(e) {
					return record, errAccess
				}
			}

			id := firewallResource(family, chain)
			spec, ok := ids[id]
			if !ok || spec.BeforeDigest != hostaction.Digest(before) || spec.AfterDigest != hostaction.Digest(desiredFirewallState(before, rules)) {
				return record, errAccess
			}
			delete(ids, id)
			record.Firewall = append(record.Firewall, RollbackFirewall{Family: family, Chain: chain, Before: before, After: desiredFirewallState(before, rules)})
		}
	}
	if len(ids) != 0 {
		return record, errAccess
	}
	n.input = &in
	return record, nil
}
func (n *nativeRuntime) inspectProfile(ctx context.Context, in generated.DebianAccessInput) error {
	if n.executableVersion != in.ProfileLock.ExecutableVersion {
		return errAccess
	}
	required := map[string]bool{"openssh-server": false, "iptables": false, "sudo": false, "passwd": false, "systemd": false}
	for _, p := range in.ProfileLock.Packages {
		if _, ok := required[p.Name]; ok {
			required[p.Name] = true
		}
	}
	for _, present := range required {
		if !present {
			return errAccess
		}
	}
	if in.RenderedAccess.RollbackUnitsDigest != RollbackUnitsDigest() {
		return errAccess
	}
	if runtime.GOARCH != "amd64" && n.root == "/" {
		return errAccess
	}
	release, e := n.read("etc/debian_version")
	if e != nil || strings.TrimSpace(string(release)) != in.ProfileLock.OSVersion {
		return errAccess
	}
	raw, e := n.read("etc/vsk-labs/debian-profile.json")
	if e != nil {
		return e
	}
	var lock generated.DebianProfileLock
	if json.Unmarshal(raw, &lock) != nil || hostaction.Digest(lock) != in.ProfileLockDigest {
		return errAccess
	}
	for _, p := range in.ProfileLock.Packages {
		got, e := n.run(ctx, "/usr/bin/dpkg-query", []string{"--show", "--showformat=${Version}", p.Name}, nil)
		if e != nil || string(got) != p.Version {
			return errAccess
		}
	}
	for _, service := range []string{"ufw.service", "firewalld.service"} {
		if _, e = n.run(ctx, "/usr/bin/systemctl", []string{"is-active", service}, nil); e == nil {
			return errAccess
		}
	}
	return nil
}
func (n *nativeRuntime) inspectAccounts(in generated.DebianAccessInput) error {
	raw, e := n.read("etc/passwd")
	if e != nil {
		return e
	}
	groups, e := n.read("etc/group")
	if e != nil {
		return e
	}
	nss, e := n.read("etc/nsswitch.conf")
	if e != nil {
		return e
	}
	for _, db := range []string{"passwd:", "group:"} {
		found := false
		for _, line := range strings.Split(string(nss), "\n") {
			f := strings.Fields(strings.SplitN(line, "#", 2)[0])
			if len(f) > 0 && f[0] == db {
				found = true
				for _, source := range f[1:] {
					if source != "files" && source != "systemd" {
						return errAccess
					}
				}
			}
		}
		if !found {
			return errAccess
		}
	}
	dangerous := map[string]bool{"root": true, "sudo": true, "admin": true, "wheel": true, "docker": true, "lxd": true, "incus-admin": true, "libvirt": true, "disk": true, "shadow": true}
	for _, a := range in.Accounts {
		if dangerous[a.Name] {
			return errAccess
		}
		accountExists := false
		for _, line := range strings.Split(string(raw), "\n") {
			v := strings.Split(line, ":")
			if len(v) != 7 {
				continue
			}
			if v[0] == a.Name || v[2] == fmt.Sprint(a.UID) {
				accountExists = true
				if v[0] != a.Name || v[2] != fmt.Sprint(a.UID) || v[3] != fmt.Sprint(a.GID) || v[5] != a.Home || v[6] != "/bin/bash" {
					return errAccess
				}
			}
		}
		if err := n.inspectHome(a, accountExists); err != nil {
			return err
		}
		for _, line := range strings.Split(string(groups), "\n") {
			v := strings.Split(line, ":")
			if len(v) != 4 {
				continue
			}
			if dangerous[v[0]] {
				if v[2] == fmt.Sprint(a.GID) {
					return errAccess
				}
				for _, member := range strings.Split(v[3], ",") {
					if member == a.Name {
						return errAccess
					}
				}
			}
			if v[0] == a.Name || v[2] == fmt.Sprint(a.GID) {
				if v[0] != a.Name || v[2] != fmt.Sprint(a.GID) {
					return errAccess
				}
			}
		}
	}
	return nil
}
func (n *nativeRuntime) inspectSSH(ctx context.Context, in generated.DebianAccessInput) error {
	raw, e := n.read("etc/ssh/sshd_config")
	if e != nil {
		return e
	}
	// OpenSSH first-value precedence: managed include must precede every operative
	// directive. Refuse an unknown earlier override instead of claiming the drop-in wins.
	first := ""
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			first = line
			break
		}
	}
	if first != "Include /etc/ssh/sshd_config.d/*.conf" {
		return errAccess
	}
	fs, e := os.OpenRoot(n.root)
	if e != nil {
		return e
	}
	defer fs.Close()
	dir, e := fs.Open("etc/ssh/sshd_config.d")
	if e != nil {
		return e
	}
	entries, e := dir.ReadDir(-1)
	dir.Close()
	if e != nil {
		return e
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".conf") && entry.Name() != "70-vsk-access.conf" {
			return errAccess
		}
	}
	if _, e = n.run(ctx, "/usr/bin/systemctl", []string{"is-active", "ssh.service"}, nil); e != nil {
		return errAccess
	}
	if _, e = n.run(ctx, "/usr/bin/systemctl", []string{"is-active", "ssh.socket"}, nil); e == nil {
		return errAccess
	}
	_, e = n.run(ctx, "/usr/sbin/sshd", []string{"-t"}, nil)
	return e
}
func firewallResource(family, chain string) string {
	prefix := "host-rules-"
	if chain == "VSK-ACCESS-DKR" {
		prefix = "container-rules-"
	}
	if family == "ipv4" {
		return prefix + "v4"
	}
	return prefix + "v6"
}
func firewallBinary(family string) string {
	if family == "ipv4" {
		return "/usr/sbin/iptables-nft"
	}
	return "/usr/sbin/ip6tables-nft"
}
func desiredFirewallState(before FirewallState, rules [][]string) FirewallState {
	if !before.ParentPresent {
		return before
	}
	return FirewallState{ParentPresent: true, Present: true, JumpPresent: true, Rules: rules}
}
func (n *nativeRuntime) inspectChain(ctx context.Context, family, chain string) (FirewallState, error) {
	state := FirewallState{Rules: [][]string{}}
	parent := "INPUT"
	if chain == "VSK-ACCESS-DKR" {
		parent = "DOCKER-USER"
	}
	raw, e := n.run(ctx, firewallBinary(family), []string{"-w", "5", "-S"}, nil)
	if e != nil {
		return state, e
	}
	jumps := 0
	parentRules := 0
	sshBanPrefix := parent == "INPUT" && validFail2banPrefix(string(raw), family)
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		if (f[0] == "-P" || f[0] == "-N") && f[1] == parent {
			state.ParentPresent = true
		}
		if f[0] == "-N" && f[1] == chain {
			state.Present = true
			continue
		}
		if f[0] == "-A" && f[1] == chain {
			rule := normalizeOwnedRule(f[2:])
			if !validOwnedRule(rule) {
				return state, errAccess
			}
			state.Rules = append(state.Rules, rule)
		}
		if f[0] == "-A" && f[1] == parent {
			if !(sshBanPrefix && parentRules == 0 && strings.Join(f, " ") == "-A INPUT -p tcp -m tcp --dport 22 -j f2b-vsk-sshd") {
				parentRules++
			}
		}
		for i := 2; i < len(f)-1; i++ {
			if (f[i] == "-j" || f[i] == "-g") && f[i+1] == chain {
				if len(f) != 4 || f[0] != "-A" || f[1] != parent || f[2] != "-j" || parentRules != 1 {
					return state, errAccess
				}
				jumps++
			}
		}
	}
	if jumps > 1 || jumps > 0 && !state.Present {
		return state, errAccess
	}
	state.JumpPresent = jumps == 1
	return state, nil
}

func (n *nativeRuntime) Arm(ctx context.Context, r RollbackRecord) error {
	if err := Arm(ctx, n.root, r); err != nil {
		return err
	}
	n.armed = &r
	if err := n.armTimer(ctx, r); err != nil {
		return err
	}
	return nil
}
func (n *nativeRuntime) ApplyConfiguration(ctx context.Context, in generated.DebianAccessInput) (RoleResult, error) {
	var result RoleResult
	err := withRollback(ctx, n.root, func(fs *os.Root) error {
		if n.armed == nil || ctx.Err() != nil {
			return errAccess
		}
		current, e := readRollback(fs)
		if e != nil || current.State != "armed" || current.Digest() != n.armed.Digest() {
			return errAccess
		}
		for _, f := range current.Files {
			raw, mode, e := readProtected(fs, f.Path)
			if f.BeforePresent {
				if e != nil || !bytes.Equal(raw, f.Before) || mode != f.BeforeMode {
					return errAccess
				}
			} else if !os.IsNotExist(e) {
				return errAccess
			}
		}
		for _, fw := range current.Firewall {
			observed, e := n.inspectChain(ctx, fw.Family, fw.Chain)
			if e != nil || hostaction.Digest(observed) != hostaction.Digest(fw.Before) {
				return errAccess
			}
		}
		result, e = n.applyConfigurationLocked(ctx, in)
		return e
	})
	return result, err
}
func (n *nativeRuntime) applyConfigurationLocked(ctx context.Context, in generated.DebianAccessInput) (RoleResult, error) {
	if n.armed == nil || n.input == nil || hostaction.Digest(*n.input) != hostaction.Digest(in) {
		return RoleResult{}, errAccess
	}
	deadline := n.armed.ArmedAt.Add(120 * time.Second)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if err := n.applyAccounts(ctx, in); err != nil {
		return RoleResult{}, err
	}
	desired, err := DesiredFiles(in)
	if err != nil {
		return RoleResult{}, err
	}
	fs, err := os.OpenRoot(n.root)
	if err != nil {
		return RoleResult{}, err
	}
	defer fs.Close()
	for _, saved := range n.armed.Files {
		if ctx.Err() != nil {
			return RoleResult{}, errAccess
		}
		current, mode, e := readProtected(fs, saved.Path)
		if saved.BeforePresent {
			if e != nil || !bytes.Equal(current, saved.Before) || mode != saved.BeforeMode {
				return RoleResult{}, errAccess
			}
		} else if !os.IsNotExist(e) {
			return RoleResult{}, errAccess
		}
		if err = writeAtomic(fs, saved.Path, desired[saved.Path], desiredFileMode(saved.Path)); err != nil {
			return RoleResult{}, err
		}
	}
	if _, err = n.run(ctx, "/usr/sbin/sshd", []string{"-t"}, nil); err != nil {
		return RoleResult{}, err
	}
	if err = n.verifyEffectiveSSH(ctx, in); err != nil {
		return RoleResult{}, err
	}
	for _, fw := range n.armed.Firewall {
		if err = n.replaceChain(ctx, fw.Family, fw.Chain, fw.After); err != nil {
			return RoleResult{}, err
		}
	}
	if _, err = n.run(ctx, "/usr/bin/systemctl", []string{"reload", "ssh.service"}, nil); err != nil {
		return RoleResult{}, err
	}
	return n.measure(in, "partial", "access-applied-awaiting-independent-probes", true), nil
}
func (n *nativeRuntime) applyAccounts(ctx context.Context, in generated.DebianAccessInput) error {
	raw, e := n.read("etc/passwd")
	if e != nil {
		return e
	}
	groups, e := n.read("etc/group")
	if e != nil {
		return e
	}
	for _, a := range in.Accounts {
		if !strings.Contains("\n"+string(groups), "\n"+a.Name+":") {
			if _, e = n.run(ctx, "/usr/sbin/groupadd", []string{"--gid", strconv.FormatInt(a.GID, 10), "--", a.Name}, nil); e != nil {
				return e
			}
		}
		if !strings.Contains("\n"+string(raw), "\n"+a.Name+":") {
			if _, e = n.run(ctx, "/usr/sbin/useradd", []string{"--uid", strconv.FormatInt(a.UID, 10), "--gid", strconv.FormatInt(a.GID, 10), "--home-dir", a.Home, "--create-home", "--key", "UMASK=077", "--shell", "/bin/bash", "--", a.Name}, nil); e != nil {
				return e
			}
		}
	}
	return nil
}
func (n *nativeRuntime) replaceChain(ctx context.Context, family, chain string, desired FirewallState) error {
	if family != "ipv4" && family != "ipv6" || chain != "VSK-ACCESS-IN" && chain != "VSK-ACCESS-DKR" {
		return errAccess
	}
	current, e := n.inspectChain(ctx, family, chain)
	if e != nil {
		return e
	}
	if !desired.ParentPresent {
		if hostaction.Digest(current) != hostaction.Digest(desired) {
			return errAccess
		}
		return nil
	}
	parent := "INPUT"
	if chain == "VSK-ACCESS-DKR" {
		parent = "DOCKER-USER"
	}
	var payload strings.Builder
	payload.WriteString("*filter\n")
	if desired.Present {
		payload.WriteString(":" + chain + " - [0:0]\n-F " + chain + "\n")
		for _, rule := range desired.Rules {
			if !validOwnedRule(rule) {
				return errAccess
			}
			payload.WriteString("-A " + chain + " " + strings.Join(rule, " ") + "\n")
		}
	}
	if current.JumpPresent && !desired.JumpPresent {
		payload.WriteString("-D " + parent + " -j " + chain + "\n")
	}
	if !current.JumpPresent && desired.JumpPresent {
		payload.WriteString("-I " + parent + " 1 -j " + chain + "\n")
	}
	if current.Present && !desired.Present {
		payload.WriteString("-F " + chain + "\n-X " + chain + "\n")
	}
	payload.WriteString("COMMIT\n")
	bin := firewallBinary(family) + "-restore"
	if _, e = n.run(ctx, bin, []string{"--wait", "5", "--noflush", "--test"}, []byte(payload.String())); e != nil {
		return e
	}
	_, e = n.run(ctx, bin, []string{"--wait", "5", "--noflush"}, []byte(payload.String()))
	return e
}

func (n *nativeRuntime) measure(in generated.DebianAccessInput, status, reason string, changed bool) RoleResult {
	ids := []string{"debian.accounts", "debian.ssh", "debian.host-firewall", "debian.container-firewall"}
	kinds := []string{"account", "ssh", "host-flow", "container-flow"}
	out := RoleResult{Changed: changed}
	for i, id := range ids {
		m := generated.AccessMeasurement{Schema: generated.SchemaIDAccessMeasurement, SchemaVersion: "1.0.0", ControlID: id, Kind: kinds[i], Status: status, SubjectHostID: in.HostID, SubjectIdentityDigest: in.HostIdentityDigest, ProfileLockDigest: in.ProfileLockDigest, ProducerID: "debian-access-native", ProducerVersion: "1.0.0", ObservedAt: n.now().Format(time.RFC3339), ConfigurationDigest: in.RenderedAccessDigest, PositiveProbeDigest: digestBytes(nil), NegativeProbeDigest: digestBytes(nil), Reason: reason}
		if id == "debian.container-firewall" && n.armed != nil {
			for _, fw := range n.armed.Firewall {
				if fw.Chain == "VSK-ACCESS-DKR" && !fw.After.ParentPresent {
					m.Status = "partial"
					m.Reason = "container-not-installed"
				}
			}
		}
		out.Measurements = append(out.Measurements, m)
	}
	return out
}
func (n *nativeRuntime) collectConfiguration(ctx context.Context, b generated.HostActionBundle, in generated.DebianAccessInput) (RoleResult, error) {
	if err := n.inspectProfile(ctx, in); err != nil {
		return RoleResult{}, err
	}
	if err := n.inspectAccounts(in); err != nil {
		return RoleResult{}, err
	}
	if err := n.inspectSudo(ctx, in); err != nil {
		return RoleResult{}, err
	}
	if err := n.inspectInterfaces(in); err != nil {
		return RoleResult{}, err
	}
	if err := n.inspectSSH(ctx, in); err != nil {
		return RoleResult{}, err
	}
	if err := n.verifyEffectiveSSH(ctx, in); err != nil {
		return RoleResult{}, err
	}
	passwd, e := n.read("etc/passwd")
	if e != nil {
		return RoleResult{}, e
	}
	for _, a := range in.Accounts {
		if !strings.Contains("\n"+string(passwd), "\n"+a.Name+":") {
			return RoleResult{}, errAccess
		}
	}
	desired, e := DesiredFiles(in)
	if e != nil {
		return RoleResult{}, e
	}
	observed := map[string]string{}
	for p, want := range desired {
		got, e := n.read(p)
		if e != nil || !bytes.Equal(got, want) {
			return RoleResult{}, errAccess
		}
		observed[resourceForFile(p)] = digestBytes(got)
	}
	containerAbsent := false
	for _, family := range []string{"ipv4", "ipv6"} {
		for _, chain := range []string{"VSK-ACCESS-IN", "VSK-ACCESS-DKR"} {
			got, e := n.inspectChain(ctx, family, chain)
			if e != nil {
				return RoleResult{}, e
			}
			rules, e := DesiredFirewallRules(in, family, chain)
			if e != nil {
				return RoleResult{}, e
			}
			if chain == "VSK-ACCESS-DKR" && !got.ParentPresent {
				containerAbsent = true
			} else if hostaction.Digest(got) != hostaction.Digest(desiredFirewallState(got, rules)) {
				return RoleResult{}, errAccess
			}
			observed[firewallResource(family, chain)] = hostaction.Digest(got)
		}
	}
	result := n.measure(in, "passed", "local-configuration-observed", false)
	for i := range result.Measurements {
		result.Measurements[i].ConfigurationDigest = hostaction.Digest(observed)
		if result.Measurements[i].ControlID == "debian.container-firewall" && containerAbsent {
			result.Measurements[i].Status = "partial"
			result.Measurements[i].Reason = "container-not-installed"
		}
	}
	return result, nil
}
func (n *nativeRuntime) verifyEffectiveSSH(ctx context.Context, in generated.DebianAccessInput) error {
	contexts := []string{}
	for _, user := range in.SSHUsers {
		for _, prefix := range in.SSHSourcePrefixes {
			contexts = append(contexts, "user="+user+",host=localhost,addr="+strings.Split(prefix, "/")[0])
		}
	}
	for _, c := range contexts {
		out, e := n.run(ctx, "/usr/sbin/sshd", []string{"-T", "-C", c}, nil)
		if e != nil || !strings.Contains(string(out), "passwordauthentication no\n") || !strings.Contains(string(out), "kbdinteractiveauthentication no\n") || !strings.Contains(string(out), "authorizedkeysfile /etc/vsk-labs/authorized_keys/%u\n") {
			return errAccess
		}
	}
	root, e := n.run(ctx, "/usr/sbin/sshd", []string{"-T", "-C", "user=root,host=localhost,addr=127.0.0.1"}, nil)
	if e != nil {
		return e
	}
	if len(in.PrivilegedServiceKeys) == 0 {
		if !strings.Contains(string(root), "permitrootlogin no\n") {
			return errAccess
		}
	} else {
		for _, required := range []string{"passwordauthentication no\n", "authenticationmethods publickey\n", "permittty no\n", "allowtcpforwarding no\n", "allowagentforwarding no\n", "authorizedkeysfile /etc/vsk-labs/service_authorized_keys/root\n"} {
			if !strings.Contains(string(root), required) {
				return errAccess
			}
		}
		if !strings.Contains(string(root), "permitrootlogin prohibit-password\n") && !strings.Contains(string(root), "permitrootlogin without-password\n") {
			return errAccess
		}
	}
	return nil
}
func (n *nativeRuntime) inspectExistingKeys(in generated.DebianAccessInput) error {
	check := func(p string, keys []string, allowRestrict bool) error {
		raw, e := n.read(p)
		if os.IsNotExist(e) {
			return nil
		}
		if e != nil {
			return e
		}
		allowed := map[string]bool{}
		for _, text := range keys {
			key, _, _, _, e := ssh.ParseAuthorizedKey([]byte(text))
			if e != nil {
				return errAccess
			}
			allowed[ssh.FingerprintSHA256(key)] = true
		}
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			key, _, options, rest, e := ssh.ParseAuthorizedKey([]byte(line))
			if e != nil || len(rest) != 0 || !allowed[ssh.FingerprintSHA256(key)] || (!onlyRestrictOptions(options) || (!allowRestrict && len(options) > 0)) {
				return errAccess
			}
		}
		return nil
	}
	for _, a := range in.Accounts {
		if e := check("etc/vsk-labs/authorized_keys/"+a.Name, a.PublicKeys, a.Role == "automation"); e != nil {
			return e
		}
	}
	for _, a := range in.Accounts {
		raw, e := n.readUserAuthorizedKeys(a)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return e
		}
		allowed := map[string]bool{}
		for _, text := range a.PublicKeys {
			key, _, _, _, e := ssh.ParseAuthorizedKey([]byte(text))
			if e != nil {
				return errAccess
			}
			allowed[ssh.FingerprintSHA256(key)] = true
		}
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			key, _, opts, rest, e := ssh.ParseAuthorizedKey([]byte(line))
			if e != nil || len(opts) > 0 || len(rest) > 0 || !allowed[ssh.FingerprintSHA256(key)] {
				return errAccess
			}
		}
	}

	serviceKeys := map[string]generated.AccessServiceKey{}
	for _, k := range in.PrivilegedServiceKeys {
		key, _, _, _, e := ssh.ParseAuthorizedKey([]byte(k.PublicKey))
		if e != nil {
			return errAccess
		}
		serviceKeys[ssh.FingerprintSHA256(key)] = k
	}
	for _, p := range []string{"root/.ssh/authorized_keys", "etc/vsk-labs/service_authorized_keys/root"} {
		raw, e := n.read(p)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return e
		}
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			key, _, options, rest, e := ssh.ParseAuthorizedKey([]byte(line))
			if e != nil || len(rest) != 0 {
				return errAccess
			}
			declared, ok := serviceKeys[ssh.FingerprintSHA256(key)]
			if !ok {
				return errAccess
			}
			prefixes := append([]string(nil), declared.SourcePrefixes...)
			sort.Strings(prefixes)
			wantFrom := `from="` + strings.Join(prefixes, ",") + `"`
			for _, option := range options {
				if option != "restrict" && option != wantFrom {
					return errAccess
				}
			}
		}
	}

	return nil
}

func onlyRestrictOptions(options []string) bool {
	return len(options) == 0 || (len(options) == 1 && options[0] == "restrict")
}
