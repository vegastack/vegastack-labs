//go:build linux || darwin

package debianaccess

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type nativeFixture struct {
	t            *testing.T
	root         string
	n            *nativeRuntime
	input        generated.DebianAccessInput
	bundle       generated.HostActionBundle
	chains       map[string]FirewallState
	events       []string
	failTimer    bool
	failFirewall bool
}

func nativeFixtureNew(t *testing.T) *nativeFixture {
	t.Helper()
	f := &nativeFixture{t: t, root: t.TempDir(), input: validInput(t), chains: map[string]FirewallState{}}
	write := func(p string, b []byte) {
		t.Helper()
		full := filepath.Join(f.root, p)
		if e := os.MkdirAll(filepath.Dir(full), 0700); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(full, b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	for _, name := range []string{"iptables", "sudo", "passwd", "systemd"} {
		f.input.ProfileLock.Packages = append(f.input.ProfileLock.Packages, generated.AccessPackage{Schema: generated.SchemaIDAccessPackage, SchemaVersion: "1.0.0", Name: name, Version: "synthetic-test"})
	}
	f.input.ProfileLockDigest = hostaction.Digest(f.input.ProfileLock)
	f.input.RenderedAccess.ProfileLockDigest = f.input.ProfileLockDigest
	f.input.RollbackSpecification.ProfileLockDigest = f.input.ProfileLockDigest
	write("etc/debian_version", []byte("13.6\n"))
	lock, _ := json.Marshal(f.input.ProfileLock)
	write("etc/vsk-labs/debian-profile.json", lock)
	write("etc/passwd", []byte("root:x:0:0:root:/root:/bin/bash\nautomation:x:1001:1001::/home/automation:/bin/bash\n"))
	write("etc/nsswitch.conf", []byte("passwd: files systemd\ngroup: files systemd\n"))
	write("etc/group", []byte("root:x:0:\nautomation:x:1001:\n"))
	write("etc/ssh/sshd_config", []byte("Include /etc/ssh/sshd_config.d/*.conf\n"))
	write("etc/ssh/sshd_config.d/70-vsk-access.conf", []byte("# previous valid policy\n"))
	write("etc/vsk-labs/authorized_keys/automation", []byte("# retained previous key\n"))
	write("proc/sys/kernel/random/boot_id", []byte("synthetic-boot\n"))
	write("etc/systemd/system/vsk-access-rollback.service", []byte(rollbackService))
	write("etc/systemd/system/vsk-access-rollback-boot.service", []byte(rollbackBootService))
	files, e := DesiredFiles(f.input)
	if e != nil {
		t.Fatal(e)
	}
	states := []generated.AccessOwnedState{}
	for p, b := range files {
		before, e := os.ReadFile(filepath.Join(f.root, p))
		if e != nil {
			t.Fatal(e)
		}
		states = append(states, generated.AccessOwnedState{Schema: generated.SchemaIDAccessOwnedState, SchemaVersion: "1.0.0", ResourceID: resourceForFile(p), BeforeDigest: digestBytes(before), AfterDigest: digestBytes(b)})
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		for _, chain := range []string{"VSK-ACCESS-IN", "VSK-ACCESS-DKR"} {
			before := FirewallState{ParentPresent: true, Rules: [][]string{}}
			f.chains[family+chain] = before
			rules, e := DesiredFirewallRules(f.input, family, chain)
			if e != nil {
				t.Fatal(e)
			}
			states = append(states, generated.AccessOwnedState{Schema: generated.SchemaIDAccessOwnedState, SchemaVersion: "1.0.0", ResourceID: firewallResource(family, chain), BeforeDigest: hostaction.Digest(before), AfterDigest: hostaction.Digest(desiredFirewallState(before, rules))})
		}
	}
	f.input.RollbackSpecification.OwnedState = states
	f.input.RollbackDigest = hostaction.Digest(f.input.RollbackSpecification)
	f.input.RenderedAccess.RollbackUnitsDigest = RollbackUnitsDigest()
	f.input.RenderedAccessDigest = hostaction.Digest(f.input.RenderedAccess)
	raw, _ := json.Marshal(f.input)
	d := digestBytes([]byte("synthetic"))
	now := time.Now().UTC()
	f.bundle = generated.HostActionBundle{Schema: generated.SchemaIDHostActionBundle, SchemaVersion: "1.0.0", ActionID: "debian.access.apply", ActionVersion: "1.0.0", ActionInput: string(raw), ActionInputDigest: digestBytes(raw), BundleID: "bundle", PlanID: "plan", RunID: "run", StepID: "step", LeaseID: "lease", HostID: f.input.HostID, DeclarationID: "declaration", AutomationPrincipalID: "automation", CredentialReferenceID: "credential", CredentialMaterialVersion: "material", PlanDigest: d, HostIdentityDigest: f.input.HostIdentityDigest, ConsoleConfirmationDigest: d, DeclarationRevision: 1, StateRevision: 1, RecoveryEpoch: 1, CallerUID: 1001, IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339)}
	os.MkdirAll(filepath.Join(f.root, "home/automation"), 0700)
	f.n = &nativeRuntime{executableVersion: "1.0.0", interfaces: func() ([]interfaceFact, error) {
		return []interfaceFact{{Name: "eth0", Index: 2, Addresses: []string{"192.0.2.2"}}}, nil
	}, homeOwnership: func(*os.File) (uint32, uint32, error) { return 1001, 1001, nil }, root: f.root, run: f.command, now: func() time.Time { return now }}
	return f
}
func (f *nativeFixture) command(_ context.Context, bin string, args []string, input []byte) ([]byte, error) {
	f.events = append(f.events, bin+" "+strings.Join(args, " "))
	switch bin {
	case "/usr/bin/cvtsudoers":
		return []byte(exactSudoJSON), nil
	case "/usr/bin/dpkg-query":
		return []byte("synthetic-test"), nil
	case "/usr/bin/systemctl":
		if len(args) == 2 && args[0] == "is-active" && (args[1] == "ufw.service" || args[1] == "firewalld.service" || (args[1] == "docker.service" && !f.chains["ipv4VSK-ACCESS-DKR"].ParentPresent)) {
			return nil, errAccess
		}
		if len(args) == 2 && args[0] == "is-active" && args[1] == "ssh.socket" {
			return nil, errAccess
		}
		if f.failTimer && (args[0] == "start" || args[0] == "restart") {
			return nil, errAccess
		}
		return []byte("active\n"), nil
	case "/usr/sbin/sshd":
		if args[0] == "-T" {
			return []byte("permitrootlogin no\nkbdinteractiveauthentication no\npasswordauthentication no\nauthorizedkeysfile /etc/vsk-labs/authorized_keys/%u\n"), nil
		}
		return nil, nil
	case "/usr/sbin/iptables-nft", "/usr/sbin/ip6tables-nft":
		family := "ipv4"
		if strings.Contains(bin, "ip6") {
			family = "ipv6"
		}
		var b strings.Builder
		b.WriteString("-P INPUT ACCEPT\n-N UNRELATED\n-A UNRELATED -j ACCEPT\n")
		if f.chains[family+"VSK-ACCESS-DKR"].ParentPresent {
			b.WriteString("-N DOCKER-USER\n")
		}
		for _, chain := range []string{"VSK-ACCESS-IN", "VSK-ACCESS-DKR"} {
			s := f.chains[family+chain]
			if s.Present {
				fmt.Fprintf(&b, "-N %s\n", chain)
				for _, r := range s.Rules {
					fmt.Fprintf(&b, "-A %s %s\n", chain, strings.Join(r, " "))
				}
			}
			if s.JumpPresent {
				parent := "INPUT"
				if chain == "VSK-ACCESS-DKR" {
					parent = "DOCKER-USER"
				}
				fmt.Fprintf(&b, "-A %s -j %s\n", parent, chain)
			}
		}
		return []byte(b.String()), nil
	case "/usr/sbin/iptables-nft-restore", "/usr/sbin/ip6tables-nft-restore":
		if f.failFirewall {
			return nil, errAccess
		}
		if args[len(args)-1] == "--test" {
			return nil, nil
		}
		family := "ipv4"
		if strings.Contains(bin, "ip6") {
			family = "ipv6"
		}
		for _, line := range strings.Split(string(input), "\n") {
			v := strings.Fields(line)
			if len(v) < 2 {
				continue
			}
			chain := v[1]
			if v[0] == "-I" || v[0] == "-D" {
				chain = v[len(v)-1]
			}
			if chain != "VSK-ACCESS-IN" && chain != "VSK-ACCESS-DKR" {
				continue
			}
			s := f.chains[family+chain]
			switch v[0] {
			case "-F":
				s.Rules = [][]string{}
				s.Present = true
			case "-A":
				s.Rules = append(s.Rules, v[2:])
			case "-I":
				s.JumpPresent = true
			case "-D":
				s.JumpPresent = false
			case "-X":
				s.Present = false
			}
			f.chains[family+chain] = s
		}
		return nil, nil
	}
	return nil, errAccess
}
func TestAccessOrdersRollbackBeforeWrite(t *testing.T) {
	f := nativeFixtureNew(t)
	f.failTimer = true
	before, _ := os.ReadFile(filepath.Join(f.root, "etc/ssh/sshd_config.d/70-vsk-access.conf"))
	h, _ := NewHandler("debian.access.apply", f.n)
	if _, e := h.Execute(context.Background(), f.bundle); e == nil {
		t.Fatal("failed timer accepted")
	}
	after, _ := os.ReadFile(filepath.Join(f.root, "etc/ssh/sshd_config.d/70-vsk-access.conf"))
	if string(before) != string(after) {
		t.Fatal("configuration changed before timer")
	}
	for _, e := range f.events {
		if strings.Contains(e, "-restore") || strings.Contains(e, "useradd") {
			t.Fatal("mutation before armed timer")
		}
	}
}
func TestNativeAccessAppliesAndRestoresOwnedEffects(t *testing.T) {
	f := nativeFixtureNew(t)
	h, _ := NewHandler("debian.access.apply", f.n)
	r, e := h.Execute(context.Background(), f.bundle)
	if e != nil {
		t.Fatal(e)
	}
	if !r.Changed || len(r.ControlMeasurements) == 0 {
		t.Fatal("missing actual result")
	}
	desired, _ := DesiredFiles(f.input)
	for p, want := range desired {
		got, e := os.ReadFile(filepath.Join(f.root, p))
		if e != nil || string(got) != string(want) {
			t.Fatal("desired file absent", p, e)
		}
	}
	if e = f.n.restore(context.Background()); e != nil {
		t.Fatal(e)
	}
	got, _ := os.ReadFile(filepath.Join(f.root, "etc/ssh/sshd_config.d/70-vsk-access.conf"))
	if string(got) != "# previous valid policy\n" {
		t.Fatal("previous policy not restored")
	}
	for _, s := range f.chains {
		if s.Present || s.JumpPresent || len(s.Rules) != 0 {
			t.Fatal("new owned chain not removed")
		}
	}
}
func TestNativeFailureRetainsArmedRecovery(t *testing.T) {
	f := nativeFixtureNew(t)
	f.failFirewall = true
	h, _ := NewHandler("debian.access.apply", f.n)
	r, e := h.Execute(context.Background(), f.bundle)
	if e != nil || r.Status != "partial" || !r.EffectObserved {
		t.Fatalf("lost mutation outcome: %#v %v", r, e)
	}
	raw, e := os.ReadFile(filepath.Join(f.root, rollbackRecordPath))
	if e != nil {
		t.Fatal(e)
	}
	var record RollbackRecord
	json.Unmarshal(raw, &record)
	if record.State != "armed" {
		t.Fatal("failure cancelled rollback")
	}
}

func TestNativeConfirmBindsActualArmedAttempt(t *testing.T) {
	for _, kind := range []string{"success", "wrong-run", "wrong-record", "expired", "late-deadline", "boot-change", "file-drift", "firewall-drift"} {
		t.Run(kind, func(t *testing.T) {
			f := nativeFixtureNew(t)
			h, _ := NewHandler("debian.access.apply", f.n)
			if _, e := h.Execute(context.Background(), f.bundle); e != nil {
				t.Fatal(e)
			}
			record := *f.n.armed
			d := digestBytes([]byte("actual-persisted-probes"))
			in := generated.AccessConfirmInput{Schema: generated.SchemaIDAccessConfirmInput, SchemaVersion: "1.0.0", HostID: f.input.HostID, HostIdentityDigest: f.input.HostIdentityDigest, ProfileLockDigest: f.input.ProfileLockDigest, RollbackDigest: f.input.RollbackDigest, ApplyOperationID: "apply", ApplyDraftDigest: d, ApplyInputDigest: f.bundle.ActionInputDigest, ProbeSpecificationDigest: d}
			ev := generated.AccessVerificationEvidence{Schema: generated.SchemaIDAccessVerificationEvidence, SchemaVersion: "1.0.0", ApplyReceiptDigest: d, RollbackRecordDigest: record.Digest(), ProbeResultsDigest: d, SequenceDigest: d, ExpiresAt: f.n.now().Add(time.Minute).Format(time.RFC3339)}
			b := f.bundle
			b.ActionID = "debian.access.confirm"
			b.StepID = "confirm"
			raw, _ := json.Marshal(in)
			b.ActionInput = string(raw)
			b.ActionInputDigest = digestBytes(raw)
			switch kind {
			case "wrong-run":
				b.RunID = "other-run"
			case "wrong-record":
				ev.RollbackRecordDigest = d
			case "expired":
				ev.ExpiresAt = f.n.now().Add(-time.Second).Format(time.RFC3339)
			case "late-deadline":
				originalNow := f.n.now()
				f.n.now = func() time.Time { return originalNow.Add(601 * time.Second) }
				ev.ExpiresAt = f.n.now().Add(time.Minute).Format(time.RFC3339)
			case "boot-change":
				os.WriteFile(filepath.Join(f.root, "proc/sys/kernel/random/boot_id"), []byte("different-boot"), 0600)
			case "file-drift":
				os.WriteFile(filepath.Join(f.root, "etc/ssh/sshd_config.d/70-vsk-access.conf"), []byte("external-change"), 0600)
			case "firewall-drift":
				s := f.chains["ipv4VSK-ACCESS-IN"]
				s.Rules = [][]string{{"-j", "ACCEPT"}}
				f.chains["ipv4VSK-ACCESS-IN"] = s
			}
			b.VerificationEvidence = &ev
			b.VerificationEvidenceDigest = hostaction.Digest(ev)
			confirm, _ := NewHandler("debian.access.confirm", f.n)
			_, e := confirm.Execute(context.Background(), b)
			if kind == "success" {
				if e != nil {
					t.Fatal(e)
				}
			} else if e == nil {
				t.Fatal("unrelated/stale confirmation accepted")
			}
			state, _ := os.ReadFile(filepath.Join(f.root, rollbackRecordPath))
			var got RollbackRecord
			json.Unmarshal(state, &got)
			if kind == "success" {
				if got.State != "confirmed" {
					t.Fatal("confirmation not durable")
				}
			} else if got.State != "armed" {
				t.Fatal("denial disarmed rollback")
			}
		})
	}
}
func TestOwnedFirewallRestoreCannotFlushSharedTables(t *testing.T) {
	f := nativeFixtureNew(t)
	rules, _ := DesiredFirewallRules(f.input, "ipv4", "VSK-ACCESS-IN")
	state := FirewallState{ParentPresent: true, Present: true, JumpPresent: true, Rules: rules}
	if e := f.n.replaceChain(context.Background(), "ipv4", "INPUT", state); e == nil {
		t.Fatal("shared chain accepted")
	}
	state.Rules = [][]string{{"-j", "ACCEPT\n-F INPUT"}}
	if e := f.n.replaceChain(context.Background(), "ipv4", "VSK-ACCESS-IN", state); e == nil {
		t.Fatal("restore directive injection accepted")
	}
}

func TestRollbackSurvivesNewRuntimeAndBoot(t *testing.T) {
	f := nativeFixtureNew(t)
	h, _ := NewHandler("debian.access.apply", f.n)
	if _, e := h.Execute(context.Background(), f.bundle); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(f.root, "proc/sys/kernel/random/boot_id"), []byte("new-boot"), 0600)
	fresh := &nativeRuntime{root: f.root, run: f.command, now: func() time.Time { return f.n.now().Add(601 * time.Second) }}
	if e := fresh.restore(context.Background()); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(filepath.Join(f.root, "etc/ssh/sshd_config.d/70-vsk-access.conf"))
	if e != nil || string(b) != "# previous valid policy\n" {
		t.Fatal("restart lost durable rollback")
	}
}
func TestNativeInspectionRejectsPrivilegeAndIdentityDrift(t *testing.T) {
	for _, kind := range []string{"sudo-group", "uid-conflict", "home-owner", "interface", "unknown-key", "package"} {
		t.Run(kind, func(t *testing.T) {
			f := nativeFixtureNew(t)
			switch kind {
			case "sudo-group":
				os.WriteFile(filepath.Join(f.root, "etc/group"), []byte("automation:x:1001:\nsudo:x:27:automation\n"), 0600)
			case "uid-conflict":
				os.WriteFile(filepath.Join(f.root, "etc/passwd"), []byte("other:x:1001:1001::/home/other:/bin/bash\n"), 0600)
			case "home-owner":
				f.n.homeOwnership = func(*os.File) (uint32, uint32, error) { return 1002, 1002, nil }
			case "interface":
				f.n.interfaces = func() ([]interfaceFact, error) {
					return []interfaceFact{{Name: "eth0", Index: 99, Addresses: []string{"192.0.2.2"}}}, nil
				}
			case "unknown-key":
				other := validInput(t)
				os.WriteFile(filepath.Join(f.root, "etc/vsk-labs/authorized_keys/automation"), []byte(other.Accounts[0].PublicKeys[0]+"\n"), 0600)
			case "package":
				original := f.n.run
				f.n.run = func(ctx context.Context, bin string, args []string, input []byte) ([]byte, error) {
					if bin == "/usr/bin/dpkg-query" {
						return []byte("changed-version"), nil
					}
					return original(ctx, bin, args, input)
				}
			}
			if _, e := f.n.Inspect(context.Background(), f.bundle, f.input); e == nil {
				t.Fatal("unsafe preimage accepted")
			}
			if _, e := os.Stat(filepath.Join(f.root, rollbackRecordPath)); !os.IsNotExist(e) {
				t.Fatal("armed after failed inspection")
			}
		})
	}
}
func TestContainerOwnershipCollectionDoesNotClaimBaseline(t *testing.T) {
	f := nativeFixtureNew(t)
	record := PreparedProbeContext{HostID: f.input.HostID, IdentityDigest: f.input.HostIdentityDigest, ContextID: "subject-container", Kind: "container", ContainerID: strings.Repeat("a", 64)}
	f.n.readContexts = func() ([]PreparedProbeContext, error) { return []PreparedProbeContext{record}, nil }
	f.n.observeContainer = func(context.Context, PreparedProbeContext) ([]generated.AccessDestinationObservation, error) {
		return []generated.AccessDestinationObservation{{Schema: generated.SchemaIDAccessDestinationObservation, SchemaVersion: "1.0.0", HostID: record.HostID, IdentityDigest: record.IdentityDigest, ContextID: record.ContextID, ContextDigest: hostaction.Digest(record), ContainerID: record.ContainerID, NetworkID: strings.Repeat("b", 64), Address: "192.0.2.33", NamespaceDigest: digestBytes([]byte("namespace")), ProcessID: 100, ProcessStart: "55", ObservedAt: f.n.now().Format(time.RFC3339)}}, nil
	}
	result, e := f.n.Collect(context.Background(), f.bundle, f.input)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, m := range result.Measurements {
		if m.ControlID == "debian.destination-ownership" {
			found = m.Status == "passed" && len(m.DestinationOwnership) == 1
		} else if m.Status == "passed" {
			t.Fatal("unapplied baseline claimed passed")
		}
	}
	if !found {
		t.Fatal("real container observation not carried")
	}
}
func TestPreDockerBaselineDoesNotClaimContainerQualification(t *testing.T) {
	f := nativeFixtureNew(t)
	for _, family := range []string{"ipv4", "ipv6"} {
		state := FirewallState{Rules: [][]string{}}
		f.chains[family+"VSK-ACCESS-DKR"] = state
		for i := range f.input.RollbackSpecification.OwnedState {
			s := &f.input.RollbackSpecification.OwnedState[i]
			if s.ResourceID == firewallResource(family, "VSK-ACCESS-DKR") {
				s.BeforeDigest = hostaction.Digest(state)
				s.AfterDigest = hostaction.Digest(state)
			}
		}
	}
	f.input.RollbackDigest = hostaction.Digest(f.input.RollbackSpecification)
	raw, _ := json.Marshal(f.input)
	f.bundle.ActionInput = string(raw)
	f.bundle.ActionInputDigest = digestBytes(raw)
	h, _ := NewHandler("debian.access.apply", f.n)
	result, e := h.Execute(context.Background(), f.bundle)
	if e != nil || result.Status != "succeeded" {
		t.Fatal("baseline blocked by absent role", e)
	}
	for _, m := range result.ControlMeasurements {
		if m.ControlID == "debian.container-firewall" && (m.Status != "partial" || m.Reason != "container-not-installed") {
			t.Fatal("missing container falsely qualified")
		}
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		if f.chains[family+"VSK-ACCESS-DKR"].Present {
			t.Fatal("invented Docker chain")
		}
	}
}

func TestOwnedFirewallJumpMustPrecedeParentRules(t *testing.T) {
	for _, pair := range [][2]string{{"INPUT", "VSK-ACCESS-IN"}, {"DOCKER-USER", "VSK-ACCESS-DKR"}} {
		for _, first := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s-first-%t", pair[0], first), func(t *testing.T) {
				jump := "-A " + pair[0] + " -j " + pair[1] + "\n"
				bypass := "-A " + pair[0] + " -j ACCEPT\n"
				rules := jump + bypass
				if !first {
					rules = bypass + jump
				}
				raw := "-N " + pair[0] + "\n-N " + pair[1] + "\n" + rules
				n := nativeRuntime{run: func(context.Context, string, []string, []byte) ([]byte, error) { return []byte(raw), nil }}
				_, err := n.inspectChain(context.Background(), "ipv4", pair[1])
				if (err == nil) != first {
					t.Fatalf("first=%t error=%v", first, err)
				}
			})
		}
	}
}
