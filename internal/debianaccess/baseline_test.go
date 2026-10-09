//go:build linux || darwin

package debianaccess

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBaselineRollbackUsesExactOwnedFilesAndServices(t *testing.T) {
	f := nativeFixtureNew(t)
	p := "etc/fail2ban/jail.d/70-vsk-sshd.local"
	if e := os.MkdirAll(filepath.Join(f.root, filepath.Dir(p)), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(f.root, p), []byte("previous"), 0600); e != nil {
		t.Fatal(e)
	}
	files := map[string][]byte{p: []byte("changed")}
	d, e := f.n.armBaseline(context.Background(), f.bundle, files, []string{"fail2ban.service"})
	if e != nil {
		t.Fatal(e)
	}
	changed, e := writeBaseline(context.Background(), f.root, d, files)
	if e != nil || !changed {
		t.Fatal(changed, e)
	}
	if e = f.n.restore(context.Background()); e != nil {
		t.Fatal(e)
	}
	got, _ := os.ReadFile(filepath.Join(f.root, p))
	if string(got) != "previous" {
		t.Fatal("baseline preimage not restored")
	}
	for _, event := range f.events {
		if strings.Contains(event, "reload ssh.service") {
			t.Fatal("baseline rollback touched unrelated SSH")
		}
	}
}
func TestBaselineWriteRefusesPreimageDrift(t *testing.T) {
	f := nativeFixtureNew(t)
	p := "etc/fail2ban/jail.d/70-vsk-sshd.local"
	os.MkdirAll(filepath.Join(f.root, filepath.Dir(p)), 0700)
	os.WriteFile(filepath.Join(f.root, p), []byte("previous"), 0600)
	files := map[string][]byte{p: []byte("changed")}
	d, e := f.n.armBaseline(context.Background(), f.bundle, files, []string{"fail2ban.service"})
	if e != nil {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(f.root, p), []byte("external"), 0600)
	if changed, e := writeBaseline(context.Background(), f.root, d, files); e == nil || changed {
		t.Fatal("external change overwritten")
	}
	got, _ := os.ReadFile(filepath.Join(f.root, p))
	if string(got) != "external" {
		t.Fatal("external content lost")
	}
}
func TestBaselineCannotArmArbitraryRootFiles(t *testing.T) {
	f := nativeFixtureNew(t)
	if _, e := f.n.armBaseline(context.Background(), f.bundle, map[string][]byte{"etc/shadow": []byte("replace")}, []string{"fail2ban.service"}); e == nil {
		t.Fatal("arbitrary root file armed")
	}
}
