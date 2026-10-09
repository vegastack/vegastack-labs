//go:build linux

package linuxrole

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"os"
	"path/filepath"
	"testing"
)

func TestProtectedRoleFileRejectsSymlinkAndWritableAncestor(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "owned"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "owned", "unit"), []byte("exact"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readProtected(root, "owned/unit", 64); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("unit", filepath.Join(root, "owned", "alias")); err != nil {
		t.Fatal(err)
	}
	if _, err := readProtected(root, "owned/alias", 64); err == nil {
		t.Fatal("symlink accepted")
	}
	if err := os.Chmod(filepath.Join(root, "owned"), 0777); err != nil {
		t.Fatal(err)
	}
	if _, err := readProtected(root, "owned/unit", 64); err == nil {
		t.Fatal("writable ancestor accepted")
	}
}
func TestRoleAtomicWriteNeverOverwritesUnreviewedTemporaryFile(t *testing.T) {
	root := t.TempDir()
	os.Mkdir(filepath.Join(root, "owned"), 0700)
	os.WriteFile(filepath.Join(root, "owned", "unit.vsk-role-new"), []byte("preserve"), 0600)
	if writeProtected(root, "owned/unit", []byte("new")) == nil {
		t.Fatal("collision accepted")
	}
	b, _ := os.ReadFile(filepath.Join(root, "owned", "unit.vsk-role-new"))
	if string(b) != "preserve" {
		t.Fatal("unknown data removed")
	}
}

func TestRoleRollbackRestoresOnlyExactOwnedUnit(t *testing.T) {
	for _, present := range []bool{false, true} {
		t.Run(map[bool]string{false: "create", true: "replace"}[present], func(t *testing.T) {
			root := t.TempDir()
			os.MkdirAll(filepath.Join(root, "etc/systemd/system"), 0700)
			os.MkdirAll(filepath.Join(root, "var/lib/vsk-labs/access-rollback"), 0700)
			p := "etc/systemd/system/vsk-ci.slice"
			os.WriteFile(filepath.Join(root, p), []byte("new"), 0600)
			data := filepath.Join(root, "preserved-data")
			os.WriteFile(data, []byte("untouched"), 0600)
			n := &nativeRuntime{root: root, run: func(_ context.Context, b string, args []string) ([]byte, error) {
				if b != "/usr/bin/systemctl" || len(args) != 1 || args[0] != "daemon-reload" {
					t.Fatal("unexpected rollback command")
				}
				return nil, nil
			}}
			r := roleUnitRollback{Path: p, Before: []byte("old"), BeforePresent: present, BeforeMode: 0644, AfterDigest: hostaction.BytesDigest([]byte("new"))}
			if e := n.restoreRoleUnit(context.Background(), r); e != nil {
				t.Fatal(e)
			}
			got, e := os.ReadFile(filepath.Join(root, p))
			if present && (e != nil || string(got) != "old") {
				t.Fatal("old unit not restored")
			}
			if !present && !os.IsNotExist(e) {
				t.Fatal("created exact unit remains")
			}
			got, _ = os.ReadFile(data)
			if string(got) != "untouched" {
				t.Fatal("data changed")
			}
		})
	}
}
func TestRoleRollbackPreservesUnexpectedReplacement(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "etc/systemd/system"), 0700)
	p := "etc/systemd/system/vsk-ci.slice"
	os.WriteFile(filepath.Join(root, p), []byte("external replacement"), 0600)
	n := &nativeRuntime{root: root}
	if n.restoreRoleUnit(context.Background(), roleUnitRollback{Path: p, AfterDigest: hostaction.BytesDigest([]byte("expected"))}) == nil {
		t.Fatal("changed preimage restored")
	}
	b, _ := os.ReadFile(filepath.Join(root, p))
	if string(b) != "external replacement" {
		t.Fatal("external bytes changed")
	}
}
func TestOwnedUnitPreimageRejectsUnrelatedService(t *testing.T) {
	in := fixture()
	unit := DesiredFiles(in)["etc/systemd/system/vsk-labs.service"]
	if !ownedUnitPreimage(in, unit) {
		t.Fatal("canonical unit rejected")
	}
	if ownedUnitPreimage(in, append(unit, []byte("ExecStartPost=/bin/false\n")...)) {
		t.Fatal("unknown service accepted")
	}
}
