//go:build linux

package linuxrole

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRoleSliceBootLinkExactAndIdempotent(t *testing.T) {
	for _, unit := range []string{"vsk-application.slice", "vsk-ci.slice", "vsk-standby.slice"} {
		t.Run(unit, func(t *testing.T) {
			root := t.TempDir()
			os.MkdirAll(filepath.Join(root, "etc/systemd/system"), 0700)
			os.WriteFile(filepath.Join(root, "etc/systemd/system", unit), []byte("fixed unit"), 0600)
			n := &nativeRuntime{root: root}
			changed, e := n.roleBootLink(unit, true)
			if e != nil || !changed {
				t.Fatal(changed, e)
			}
			target, e := os.Readlink(filepath.Join(root, roleWantsDirectory, unit))
			if e != nil || target != "/etc/systemd/system/"+unit {
				t.Fatal(target, e)
			}
			changed, e = n.roleBootLink(unit, true)
			if e != nil || changed {
				t.Fatal("idempotency", changed, e)
			}
			if e = n.removeRoleBootLink(unit); e != nil {
				t.Fatal(e)
			}
			if _, e = os.Lstat(filepath.Join(root, roleWantsDirectory, unit)); !os.IsNotExist(e) {
				t.Fatal("created boot dependency not removed")
			}
			if _, e = os.Stat(filepath.Join(root, "etc/systemd/system", unit)); e != nil {
				t.Fatal("unit was removed")
			}
		})
	}
}
func TestRoleSliceBootLinkPreservesUnknownPreimage(t *testing.T) {
	for _, kind := range []string{"wrong-target", "regular-file", "ancestor-link"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			os.MkdirAll(filepath.Join(root, roleWantsDirectory), 0700)
			p := filepath.Join(root, roleWantsDirectory, "vsk-ci.slice")
			switch kind {
			case "wrong-target":
				os.Symlink("/etc/systemd/system/unrelated.service", p)
			case "regular-file":
				os.WriteFile(p, []byte("preserve"), 0600)
			case "ancestor-link":
				os.Remove(filepath.Join(root, roleWantsDirectory))
				os.Symlink("/tmp", filepath.Join(root, roleWantsDirectory))
			}
			n := &nativeRuntime{root: root}
			if _, e := n.roleBootLink("vsk-ci.slice", true); e == nil {
				t.Fatal("unknown preimage accepted")
			}
			if n.removeRoleBootLink("vsk-ci.slice") == nil {
				t.Fatal("unknown preimage removed")
			}
		})
	}
}

func TestRoleTmpfilesOnlyCreatesExactRuntimeDirectory(t *testing.T) {
	in := fixture()
	in.RoleID = "ci"
	files := DesiredFiles(in)
	want := "d /run/vsk-ci 0700 1000 1000 -\n"
	if string(files[TmpfilesPath(in.RoleID)]) != want {
		t.Fatal(string(files[TmpfilesPath(in.RoleID)]))
	}
	if !strings.Contains(string(files["etc/systemd/system/vsk-ci.slice"]), "[Install]\nWantedBy=multi-user.target\n") {
		t.Fatal("slice is not boot enabled")
	}
	if !ownedTmpfilesPreimage(in, []byte(want)) || ownedTmpfilesPreimage(in, []byte(want+"R /srv/data - - - -\n")) {
		t.Fatal("tmpfiles preimage not finite")
	}
}
func TestRoleTmpfilesConflictRefusesBeforeAccountEffects(t *testing.T) {
	root := t.TempDir()
	for _, p := range []string{"etc/systemd/system", "etc/tmpfiles.d", "var/lib/vsk-labs/access-rollback", "proc/sys/kernel"} {
		os.MkdirAll(filepath.Join(root, p), 0700)
	}
	os.WriteFile(filepath.Join(root, "proc/meminfo"), []byte("MemTotal: 4194304 kB\n"), 0600)
	os.WriteFile(filepath.Join(root, "proc/sys/kernel/threads-max"), []byte("1000\n"), 0600)
	in := fixture()
	in.RoleID = "ci"
	in.Resources.CapacityCPUPercent = 100
	in.Resources.MinimumFreeBytes = 1
	in.Resources.MinimumFreePercent = 1
	bad := []byte("d /run/unrelated 0700 1000 1000 -\n")
	os.WriteFile(filepath.Join(root, TmpfilesPath(in.RoleID)), bad, 0600)
	in.ExpectedTmpfilesDigest = hostaction.BytesDigest(bad)
	called := false
	n := &nativeRuntime{root: root, run: func(context.Context, string, []string) ([]byte, error) { called = true; return nil, errNative }}
	out, e := n.Apply(context.Background(), generated.HostActionBundle{}, in)
	if e == nil || out.Changed || called {
		t.Fatal("conflict reached native effects", out, e, called)
	}
	got, _ := os.ReadFile(filepath.Join(root, TmpfilesPath(in.RoleID)))
	if string(got) != string(bad) {
		t.Fatal("unknown config changed")
	}
}
func TestTmpfilesRollbackPreservesRuntimeData(t *testing.T) {
	root := t.TempDir()
	for _, p := range []string{"etc/tmpfiles.d", "var/lib/vsk-labs/access-rollback", "run/vsk-ci"} {
		os.MkdirAll(filepath.Join(root, p), 0700)
	}
	p := "etc/tmpfiles.d/vsk-ci.conf"
	os.WriteFile(filepath.Join(root, p), []byte("new"), 0600)
	os.WriteFile(filepath.Join(root, "run/vsk-ci/data"), []byte("preserve"), 0600)
	n := &nativeRuntime{root: root, run: func(context.Context, string, []string) ([]byte, error) { return nil, nil }}
	if e := n.restoreRoleUnit(context.Background(), roleUnitRollback{Path: p, BeforePresent: false, AfterDigest: hostaction.BytesDigest([]byte("new"))}); e != nil {
		t.Fatal(e)
	}
	got, e := os.ReadFile(filepath.Join(root, "run/vsk-ci/data"))
	if e != nil || string(got) != "preserve" {
		t.Fatal("runtime data removed")
	}
}
