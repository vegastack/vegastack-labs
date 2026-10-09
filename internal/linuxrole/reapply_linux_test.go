//go:build linux

package linuxrole

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

func controlReapplyFixture(t *testing.T) (*nativeRuntime, generated.LinuxRoleInput, *[]string, *string) {
	t.Helper()
	root := t.TempDir()
	in := fixture()
	uid, gid := int64(os.Geteuid()), int64(os.Getegid())
	// This filesystem fixture uses its actual test owner. Request-level non-root
	// validation is separately covered; it does not create or qualify an OS user.
	in.Accounts[0].UID = uid
	in.Accounts[0].GID = gid
	in.Resources.CapacityCPUPercent = 100
	in.Resources.MinimumFreeBytes = 1
	in.Resources.MinimumFreePercent = 1
	in.ControlIDs = []string{"linux.role-service-resources"}
	for _, p := range []string{"var/lib/vsk-labs/access-rollback", "etc/systemd/system", "usr/local/bin", "proc/sys/kernel", "sys/fs/cgroup/system.slice/vsk-labs.service"} {
		if e := os.MkdirAll(filepath.Join(root, p), 0700); e != nil {
			t.Fatal(e)
		}
	}
	for i := range in.Directories {
		d := &in.Directories[i]
		d.UID = uid
		d.GID = gid
		d.ExpectedState = "owned"
		p := DirectoryPath(in.RoleID, d.Selector)
		d.ExpectedDigest = directoryDigest(p, uid, gid, d.Mode)
		if e := os.MkdirAll(filepath.Join(root, p), 0700); e != nil {
			t.Fatal(e)
		}
	}
	files := map[string][]byte{"proc/meminfo": []byte("MemTotal: 4194304 kB\n"), "proc/sys/kernel/threads-max": []byte("1000\n"), "usr/local/bin/vsk-labs": []byte("verified executable fixture"), "etc/vsk-labs/control/server.json": []byte("{}"), "sys/fs/cgroup/system.slice/vsk-labs.service/memory.max": []byte(strconv.FormatInt(in.Resources.MemoryMaxBytes, 10)), "sys/fs/cgroup/system.slice/vsk-labs.service/pids.max": []byte(strconv.FormatInt(in.Resources.TasksMax, 10)), "sys/fs/cgroup/system.slice/vsk-labs.service/cpu.max": []byte("100000 100000")}
	for p, b := range files {
		if e := os.WriteFile(filepath.Join(root, p), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	in.ExecutableDigest = hostaction.BytesDigest(files["usr/local/bin/vsk-labs"])
	in.ConfigDigest = hostaction.BytesDigest(files["etc/vsk-labs/control/server.json"])
	unit := DesiredFiles(in)["etc/systemd/system/vsk-labs.service"]
	os.WriteFile(filepath.Join(root, "etc/systemd/system/vsk-labs.service"), unit, 0600)
	in.ExpectedServiceState = "active"
	in.ExpectedUnitDigest = hostaction.BytesDigest(unit)
	active := "active"
	mutations := []string{}
	n := &nativeRuntime{root: root, now: time.Now, run: func(_ context.Context, bin string, args []string) ([]byte, error) {
		if bin == "/usr/bin/getent" && len(args) == 2 && args[0] == "passwd" && args[1] == "vsk-labs" {
			return []byte(fmt.Sprintf("vsk-labs:x:%d:%d::/nonexistent:/usr/sbin/nologin\n", uid, gid)), nil
		}
		if bin == "/usr/bin/id" && len(args) == 2 && args[0] == "-G" {
			return []byte(strconv.FormatInt(gid, 10)), nil
		}
		if bin == "/usr/bin/systemctl" && args[0] == "show" {
			if args[2] == "--property=ActiveState" {
				return []byte(active), nil
			}
			return []byte(fmt.Sprintf("MemoryMax=%d\nTasksMax=%d\nCPUQuotaPerSecUSec=1s\nActiveState=%s\nUser=%d\nGroup=%d\nMainPID=1234\nFragmentPath=/etc/systemd/system/vsk-labs.service\nControlGroup=/system.slice/vsk-labs.service\nDropInPaths=\nUnitFileState=enabled\n", in.Resources.MemoryMaxBytes, in.Resources.TasksMax, active, uid, gid)), nil
		}
		mutations = append(mutations, bin+" "+strings.Join(args, " "))
		if bin == "/usr/bin/systemctl" && len(args) == 1 && args[0] == "daemon-reload" {
			return nil, nil
		}
		return nil, errNative
	}}
	return n, in, &mutations, &active
}
func TestActiveControlReapplyIsVerificationOnly(t *testing.T) {
	n, in, mutations, _ := controlReapplyFixture(t)
	unitPath := filepath.Join(n.root, "etc/systemd/system/vsk-labs.service")
	before, _ := os.Stat(unitPath)
	body, _ := os.ReadFile(unitPath)
	out, e := n.Apply(context.Background(), generated.HostActionBundle{}, in)
	after, _ := os.Stat(unitPath)
	current, _ := os.ReadFile(unitPath)
	if e != nil || out.Changed || len(*mutations) != 0 || len(out.Measurements) != 1 || out.Measurements[0].Status != "passed" || !os.SameFile(before, after) || !bytes.Equal(body, current) {
		t.Fatal("active reapply mutated or failed", out, e, *mutations)
	}
	if _, e = os.Lstat(filepath.Join(n.root, roleJournalPath)); !os.IsNotExist(e) {
		t.Fatal("verification-only wrote journal")
	}
}
func TestActiveControlRejectsDifferentConfigurationWithoutEffects(t *testing.T) {
	for _, kind := range []string{"unit", "config", "executable", "account", "directory"} {
		t.Run(kind, func(t *testing.T) {
			n, in, mutations, _ := controlReapplyFixture(t)
			switch kind {
			case "unit":
				in.Resources.TasksMax++
			case "config":
				in.ConfigDigest = hostaction.Digest("different-config")
			case "executable":
				in.ExecutableDigest = hostaction.Digest("different-executable")
			case "account":
				in.Accounts[0].UID++
			case "directory":
				in.Directories[0].Mode = "0750"
			}
			out, e := n.Apply(context.Background(), generated.HostActionBundle{}, in)
			if e == nil || out.Changed || len(*mutations) != 0 {
				t.Fatal("active difference reached mutation", out, e, *mutations)
			}
		})
	}
}
func TestSuccessfulInstallClosesJournalBeforeActiveReapply(t *testing.T) {
	n, in, mutations, active := controlReapplyFixture(t)
	os.Remove(filepath.Join(n.root, "etc/systemd/system/vsk-labs.service"))
	*active = "inactive"
	in.ExpectedServiceState = "absent"
	in.ExpectedUnitDigest = ""
	out, e := n.Apply(context.Background(), generated.HostActionBundle{}, in)
	if e != nil || !out.Changed {
		t.Fatal(out, e)
	}
	var journal []roleUnitRollback
	raw, _ := os.ReadFile(filepath.Join(n.root, roleJournalPath))
	if json.Unmarshal(raw, &journal) != nil || len(journal) != 1 || journal[0].Status != "completed" {
		t.Fatal("successful install left unresolved journal", string(raw))
	}
	*mutations = nil
	*active = "active"
	in.ExpectedServiceState = "active"
	in.ExpectedUnitDigest = hostaction.BytesDigest(DesiredFiles(in)["etc/systemd/system/vsk-labs.service"])
	out, e = n.Apply(context.Background(), generated.HostActionBundle{}, in)
	if e != nil || out.Changed || len(*mutations) != 0 {
		t.Fatal("completed journal blocked exact active reapply", out, e, *mutations)
	}
	after, _ := os.ReadFile(filepath.Join(n.root, roleJournalPath))
	if !bytes.Equal(raw, after) {
		t.Fatal("no-op rewrote prior journal")
	}
}
func TestInterruptedTwoFileInstallRetryPreservesOriginalPreimages(t *testing.T) {
	n, in, mutations, _ := controlReapplyFixture(t)
	in.RoleID = "ci"
	os.MkdirAll(filepath.Join(n.root, "etc/tmpfiles.d"), 0700)
	unitPath := "etc/systemd/system/vsk-ci.slice"
	oldUnit := []byte("original unit before interrupted installation")
	newUnit := DesiredFiles(in)[unitPath]
	os.WriteFile(filepath.Join(n.root, unitPath), newUnit, 0600)
	oldConfig := []byte("original tmpfiles before interrupted installation")
	os.WriteFile(filepath.Join(n.root, TmpfilesPath(in.RoleID)), oldConfig, 0600)
	journal := []roleUnitRollback{{Path: unitPath, Before: oldUnit, BeforePresent: true, BeforeMode: 0600, AfterDigest: hostaction.BytesDigest(newUnit), BundleDigest: hostaction.Digest("interrupted-plan"), Status: "pending"}}
	raw, _ := json.Marshal(journal)
	os.WriteFile(filepath.Join(n.root, roleJournalPath), raw, 0600)
	for attempt := 0; attempt < 2; attempt++ {
		out, e := n.Apply(context.Background(), generated.HostActionBundle{}, in)
		if e == nil || out.Changed || len(*mutations) != 0 {
			t.Fatal("retry discarded unresolved journal", out, e)
		}
		after, _ := os.ReadFile(filepath.Join(n.root, roleJournalPath))
		config, _ := os.ReadFile(filepath.Join(n.root, TmpfilesPath(in.RoleID)))
		if !bytes.Equal(raw, after) || !bytes.Equal(config, oldConfig) {
			t.Fatal("original evidence or untouched second file changed")
		}
	}
}
func TestActiveControlCannotBypassUnresolvedJournal(t *testing.T) {
	n, in, mutations, _ := controlReapplyFixture(t)
	raw, _ := json.Marshal([]roleUnitRollback{{Path: "etc/systemd/system/vsk-labs.service", Status: "pending", Before: []byte("preserve"), AfterDigest: in.ExpectedUnitDigest, BundleDigest: hostaction.Digest("old")}})
	os.WriteFile(filepath.Join(n.root, roleJournalPath), raw, 0600)
	out, e := n.Apply(context.Background(), generated.HostActionBundle{}, in)
	if e == nil || out.Changed || len(*mutations) != 0 {
		t.Fatal("active no-op bypassed unresolved journal")
	}
	after, _ := os.ReadFile(filepath.Join(n.root, roleJournalPath))
	if !bytes.Equal(raw, after) {
		t.Fatal("prior journal rewritten")
	}
}
