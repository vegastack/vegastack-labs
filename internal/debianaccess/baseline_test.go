//go:build linux || darwin

package debianaccess

import (
	"context"
	"encoding/json"
	"fmt"
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

func TestBaselineRestoresStoppedServiceAndDefersBootVerification(t *testing.T) {
	for _, boot := range []bool{false, true} {
		t.Run(fmt.Sprint(boot), func(t *testing.T) {
			f := nativeFixtureNew(t)
			state := "inactive"
			started := false
			f.n.run = func(_ context.Context, bin string, args []string, _ []byte) ([]byte, error) {
				if args[0] == "show" {
					return []byte(state), nil
				}
				if strings.Join(args, " ") == "start fail2ban.service" {
					state = "active"
					started = true
					return nil, nil
				}
				if strings.Join(args, " ") == "--no-block start fail2ban.service" {
					started = true
					return nil, nil
				}
				t.Fatal("unexpected or blocking boot operation", args)
				return nil, errAccess
			}
			if e := f.n.restoreBaselineService(context.Background(), "fail2ban.service", "active", boot); e != nil || !started {
				t.Fatal(e, started)
			}
			if boot && state != "inactive" {
				t.Fatal("enqueue reported active")
			}
		})
	}
}
func TestBaselineAbsentProfilesRollbackAfterPartialLoad(t *testing.T) {
	f := nativeFixtureNew(t)
	os.MkdirAll(filepath.Join(f.root, "etc/apparmor.d"), 0700)
	profiles := []BaselineProfile{}
	for _, name := range []string{"first", "second"} {
		raw := []byte("profile " + name + " { }\n")
		os.WriteFile(filepath.Join(f.root, "etc/apparmor.d", name), raw, 0600)
		profiles = append(profiles, BaselineProfile{File: "etc/apparmor.d/" + name, Name: name, Digest: digestBytes(raw)})
	}
	loaded := map[string]string{}
	original := f.n.run
	f.n.run = func(ctx context.Context, bin string, args []string, b []byte) ([]byte, error) {
		if bin == "/usr/sbin/aa-status" {
			return json.Marshal(map[string]any{"profiles": loaded})
		}
		if bin == "/usr/sbin/apparmor_parser" {
			name := filepath.Base(args[len(args)-1])
			switch args[0] {
			case "--names":
				return []byte(name), nil
			case "--add":
				if name == "second" {
					return nil, errAccess
				}
				loaded[name] = "enforce"
				return nil, nil
			case "--remove":
				delete(loaded, name)
				return nil, nil
			}
			t.Fatal(args)
		}
		return original(ctx, bin, args, b)
	}
	d, e := f.n.armBaselineProfiles(context.Background(), f.bundle, nil, nil, profiles)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.n.loadBaselineProfiles(context.Background(), d); e == nil || loaded["first"] != "enforce" {
		t.Fatal("missing partial effect", e, loaded)
	}
	if e = f.n.restore(context.Background()); e != nil || len(loaded) != 0 {
		t.Fatal("partial profile not restored", e, loaded)
	}
}

func TestBaselineBootRestorationRemainsPendingUntilServiceObserved(t *testing.T) {
	f := nativeFixtureNew(t)
	p := "etc/fail2ban/jail.d/70-vsk-sshd.local"
	os.MkdirAll(filepath.Join(f.root, filepath.Dir(p)), 0700)
	os.WriteFile(filepath.Join(f.root, p), []byte("before"), 0600)
	files := map[string][]byte{p: []byte("after")}
	d, e := f.n.armBaseline(context.Background(), f.bundle, files, []string{"fail2ban.service"})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = writeBaseline(context.Background(), f.root, d, files); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(f.root, "proc/sys/kernel/random/boot_id"), []byte("next-boot"), 0600)
	state := "inactive"
	queued := false
	original := f.n.run
	f.n.run = func(ctx context.Context, bin string, args []string, b []byte) ([]byte, error) {
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "fail2ban.service") {
			if args[0] == "show" {
				return []byte(state), nil
			}
			if joined == "--no-block start fail2ban.service" {
				queued = true
				return nil, nil
			}
			if joined == "reload fail2ban.service" && state == "active" {
				return nil, nil
			}
			t.Fatal("unsafe early boot action", args)
		}
		return original(ctx, bin, args, b)
	}
	if e = f.n.restore(context.Background()); e != nil || !queued {
		t.Fatal(e, queued)
	}
	fs, e := os.OpenRoot(f.root)
	if e != nil {
		t.Fatal(e)
	}
	defer fs.Close()
	r, e := readRollback(fs)
	if e != nil || r.State != "services-pending" {
		t.Fatal(r.State, e)
	}
	state = "active"
	if e = f.n.restore(context.Background()); e != nil {
		t.Fatal(e)
	}
	r, e = readRollback(fs)
	if e != nil || r.State != "restored" {
		t.Fatal(r.State, e)
	}
}

func TestBaselineBootRollbackFollowsAppArmorLoad(t *testing.T) {
	if !strings.Contains(rollbackBootService, "After=local-fs.target apparmor.service\n") || !strings.Contains(rollbackBootService, "Before=network-pre.target ssh.service ssh.socket docker.service") {
		t.Fatal("boot profile recovery ordering lost")
	}
}
