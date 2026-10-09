//go:build linux || darwin

package debianaccess

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

func TestNativeBootReloadsOnlyProtectedOwnedPolicy(t *testing.T) {
	for _, state := range []string{"armed", "confirmed", "restored"} {
		t.Run(state, func(t *testing.T) {
			f := nativeFixtureNew(t)
			h, _ := NewHandler("debian.access.apply", f.n)
			if _, e := h.Execute(context.Background(), f.bundle); e != nil {
				t.Fatal(e)
			}
			var saved RollbackRecord
			e := withRollback(context.Background(), f.root, func(fs *os.Root) error {
				r, e := readRollback(fs)
				if e != nil {
					return e
				}
				// Model an existing previous owned baseline, distinct from new policy.
				for i := range r.Firewall {
					r.Firewall[i].Before = FirewallState{ParentPresent: true, Present: true, JumpPresent: true, Rules: [][]string{{"-j", "RETURN"}}}
				}
				if state == "confirmed" {
					r.State = "confirmed"
					r.ProbeDigest = hostaction.Digest("actual synthetic probe")
				}
				saved = r
				return saveRollback(fs, r)
			})
			if e != nil {
				t.Fatal(e)
			}
			if state == "restored" {
				if e = f.n.restore(context.Background()); e != nil {
					t.Fatal(e)
				}
			}
			for k := range f.chains {
				f.chains[k] = FirewallState{ParentPresent: strings.HasSuffix(k, "VSK-ACCESS-IN"), Rules: [][]string{}}
			}
			os.WriteFile(filepath.Join(f.root, "proc/sys/kernel/random/boot_id"), []byte("boot-two"), 0600)
			f.n.run = func(ctx context.Context, bin string, args []string, in []byte) ([]byte, error) {
				if len(args) == 4 && args[2] == "-N" && args[3] == "DOCKER-USER" {
					family := "ipv4"
					if strings.Contains(bin, "ip6") {
						family = "ipv6"
					}
					s := f.chains[family+"VSK-ACCESS-DKR"]
					s.ParentPresent = true
					f.chains[family+"VSK-ACCESS-DKR"] = s
					return nil, nil
				}
				return f.command(ctx, bin, args, in)
			}
			if e = f.n.restore(context.Background()); e != nil {
				t.Fatal(e)
			}
			for _, fw := range saved.Firewall {
				want := fw.Before
				if state == "confirmed" {
					want = fw.After
				}
				if hostaction.Digest(f.chains[fw.Family+fw.Chain]) != hostaction.Digest(want) {
					t.Fatal("recorded firewall was not restored", fw.Chain)
				}
			}
			withRollback(context.Background(), f.root, func(fs *os.Root) error {
				r, e := readRollback(fs)
				if e != nil {
					t.Fatal(e)
				}
				if r.ReconciledBootID != "boot-two" {
					t.Fatal("boot completion not persisted")
				}
				return nil
			})
			// Same boot cannot use the old signed boot ID to reapply vanished chains.
			key := "ipv4VSK-ACCESS-IN"
			f.chains[key] = FirewallState{ParentPresent: true, Rules: [][]string{}}
			if e = f.n.restore(context.Background()); e != nil {
				t.Fatal(e)
			}
			if f.chains[key].Present {
				t.Fatal("same boot treated as another kernel reset")
			}
		})
	}
}

func TestNativeBootPreservesUnknownOwnedRules(t *testing.T) {
	f := nativeFixtureNew(t)
	h, _ := NewHandler("debian.access.apply", f.n)
	if _, e := h.Execute(context.Background(), f.bundle); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(f.root, "proc/sys/kernel/random/boot_id"), []byte("boot-two"), 0600)
	bad := FirewallState{ParentPresent: true, Present: true, JumpPresent: true, Rules: [][]string{{"-j", "DROP"}}}
	f.chains["ipv4VSK-ACCESS-IN"] = bad
	if e := f.n.restore(context.Background()); e == nil {
		t.Fatal("unknown reboot policy accepted")
	}
	if hostaction.Digest(f.chains["ipv4VSK-ACCESS-IN"]) != hostaction.Digest(bad) {
		t.Fatal("unknown policy overwritten")
	}
}

func TestNativeBootDoesNotInventDockerForPreRoleBaseline(t *testing.T) {
	f := nativeFixtureNew(t)
	empty := FirewallState{Rules: [][]string{}}
	f.chains["ipv4VSK-ACCESS-DKR"] = empty
	r := RollbackRecord{Firewall: []RollbackFirewall{{Family: "ipv4", Chain: "VSK-ACCESS-DKR", Before: empty, After: empty}}}
	if e := f.n.restoreFirewall(context.Background(), r, true, true); e != nil {
		t.Fatal(e)
	}
	if f.chains["ipv4VSK-ACCESS-DKR"].ParentPresent {
		t.Fatal("created Docker parent for absent role")
	}
	for _, event := range f.events {
		if strings.Contains(event, "-N DOCKER-USER") {
			t.Fatal("issued Docker parent creation")
		}
	}
}

func TestNativePreparedBootMissingRecordOnlyIsHarmless(t *testing.T) {
	f := nativeFixtureNew(t)
	if e := f.n.restore(context.Background()); e != nil {
		t.Fatal("prepared host without an apply blocked", e)
	}
	if e := os.WriteFile(filepath.Join(f.root, rollbackRecordPath), []byte("corrupt"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := f.n.restore(context.Background()); e == nil {
		t.Fatal("corrupted record treated as no prior apply")
	}
}
