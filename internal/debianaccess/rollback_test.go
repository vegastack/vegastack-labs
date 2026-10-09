//go:build linux || darwin

package debianaccess

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRollbackRestoresOnlyOwnedSnapshot(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "etc/ssh/sshd_config.d/70-vsk-access.conf")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("before"), 0600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)
	r := RollbackRecord{HostID: "synthetic", HostIdentityDigest: digestBytes([]byte("host")), PlanID: "plan", InputDigest: digestBytes([]byte("input")), AuthorizationDigest: digestBytes([]byte("spec")), BundleDigest: digestBytes([]byte("bundle")), BootID: "synthetic-boot", ArmedAt: now, Deadline: now.Add(600 * time.Second), State: "armed", Files: []RollbackFile{{Path: "etc/ssh/sshd_config.d/70-vsk-access.conf", Before: []byte("before"), BeforePresent: true, BeforeMode: 0600, AfterMode: 0600, AfterDigest: digestBytes([]byte("after"))}}}
	if err := Arm(context.Background(), root, r); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("after"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Restore(context.Background(), root, r.Digest()); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "before" {
		t.Fatalf("restore: %q %v", got, err)
	}
	if err := Restore(context.Background(), root, r.Digest()); err != nil {
		t.Fatalf("idempotent restore: %v", err)
	}
}

func TestRollbackRefusesExternalModification(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "etc/ssh/sshd_config.d/70-vsk-access.conf")
	os.MkdirAll(filepath.Dir(path), 0700)
	os.WriteFile(path, []byte("before"), 0600)
	now := time.Now().UTC()
	r := RollbackRecord{HostID: "synthetic", HostIdentityDigest: digestBytes([]byte("host")), PlanID: "plan", InputDigest: digestBytes([]byte("input")), AuthorizationDigest: digestBytes([]byte("spec")), BundleDigest: digestBytes([]byte("bundle")), BootID: "boot", ArmedAt: now, Deadline: now.Add(600 * time.Second), State: "armed", Files: []RollbackFile{{Path: "etc/ssh/sshd_config.d/70-vsk-access.conf", Before: []byte("before"), BeforePresent: true, BeforeMode: 0600, AfterMode: 0600, AfterDigest: digestBytes([]byte("after"))}}}
	if err := Arm(context.Background(), root, r); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(path, []byte("someone-else"), 0600)
	if err := Restore(context.Background(), root, r.Digest()); err == nil {
		t.Fatal("overwrote external change")
	}
	got, _ := os.ReadFile(path)
	if string(got) != "someone-else" {
		t.Fatal("external change destroyed")
	}
}

func rollbackFixture(t *testing.T) (string, RollbackRecord, string) {
	t.Helper()
	root := t.TempDir()
	p := filepath.Join(root, "etc/ssh/sshd_config.d/70-vsk-access.conf")
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("before"), 0600); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	r := RollbackRecord{HostID: "synthetic", HostIdentityDigest: digestBytes([]byte("host")), PlanID: "plan", InputDigest: digestBytes([]byte("input")), AuthorizationDigest: digestBytes([]byte("spec")), BundleDigest: digestBytes([]byte("bundle")), BootID: "boot", ArmedAt: now, Deadline: now.Add(600 * time.Second), State: "armed", Files: []RollbackFile{{Path: "etc/ssh/sshd_config.d/70-vsk-access.conf", Before: []byte("before"), BeforePresent: true, BeforeMode: 0600, AfterMode: 0600, AfterDigest: digestBytes([]byte("after"))}}}
	return root, r, p
}
func TestRollbackRefusesUnsafeSnapshots(t *testing.T) {
	for _, kind := range []string{"traversal", "symlink", "hardlink", "before-drift", "deadline", "overlap", "corrupt-record"} {
		t.Run(kind, func(t *testing.T) {
			root, r, p := rollbackFixture(t)
			switch kind {
			case "traversal":
				r.Files[0].Path = "../escape"
			case "symlink":
				os.Rename(p, p+".saved")
				os.Symlink(p+".saved", p)
			case "hardlink":
				os.Link(p, p+".hardlink")
			case "before-drift":
				os.WriteFile(p, []byte("changed"), 0600)
			case "deadline":
				r.Deadline = r.Deadline.Add(time.Second)
			case "overlap":
				if err := Arm(context.Background(), root, r); err != nil {
					t.Fatal(err)
				}
			case "corrupt-record":
				os.MkdirAll(filepath.Join(root, rollbackDirectory), 0700)
				os.WriteFile(filepath.Join(root, rollbackRecordPath), []byte("not-json"), 0600)
			}
			if err := Arm(context.Background(), root, r); err == nil {
				t.Fatal("unsafe snapshot accepted")
			}
		})
	}
}
func TestRollbackConfirmationRequiresExactFreshAppliedState(t *testing.T) {
	for _, kind := range []string{"good", "wrong-record", "wrong-probe", "deadline", "clock-backward", "not-applied"} {
		t.Run(kind, func(t *testing.T) {
			root, r, p := rollbackFixture(t)
			if err := Arm(context.Background(), root, r); err != nil {
				t.Fatal(err)
			}
			if kind != "not-applied" {
				os.WriteFile(p, []byte("after"), 0600)
			}
			now := r.ArmedAt.Add(time.Second)
			d := r.Digest()
			probe := digestBytes([]byte("independent-probes"))
			switch kind {
			case "wrong-record":
				d = digestBytes([]byte("other"))
			case "wrong-probe":
				probe = "true"
			case "deadline":
				now = r.Deadline
			case "clock-backward":
				now = r.ArmedAt.Add(-time.Second)
			}
			err := confirmAt(context.Background(), root, d, probe, now)
			if kind == "good" {
				if err != nil {
					t.Fatal(err)
				}
				if err = Restore(context.Background(), root, d); err == nil {
					t.Fatal("confirmed configuration rolled back")
				}
			} else if err == nil {
				t.Fatal("unqualified confirmation accepted")
			}
		})
	}
}
