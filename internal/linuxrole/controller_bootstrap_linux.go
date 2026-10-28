//go:build linux

package linuxrole

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"golang.org/x/sys/unix"
)

func controllerMachine(root string) (string, error) {
	b, e := ownedFile(path.Join(root, "etc/machine-id"), 0, 64)
	if e != nil {
		return "", e
	}
	return strings.TrimSpace(string(b)), nil
}

// VerifyControllerInstallPreconditions observes only the fixed initial effect's
// preimages. The API still owns current policy, approval, run and lease checks.
func VerifyControllerInstallPreconditions(ctx context.Context, in ControllerInstallInput) error {
	if ValidateControllerInstallInput(in) != nil {
		return errInput
	}
	n := NewNativeRuntime("").(*nativeRuntime)
	_, e := n.controllerFoundationPreflight(ctx, in)
	return e
}

func (n *nativeRuntime) controllerFoundationPreflight(ctx context.Context, in ControllerInstallInput) (map[string][]byte, error) {
	machine, e := controllerMachine(n.root)
	if e != nil {
		return nil, e
	}
	files, e := ControllerFoundationFiles(in, machine)
	if e != nil {
		return nil, e
	}
	for _, f := range []struct {
		p, d  string
		uid   int64
		limit int64
	}{
		{"/etc/vsk-labs/control/server.json", in.ConfigDigest, in.AdministratorUID, 1 << 20},
		{ControllerRecoveryImage, in.RecoveryImageDigest, in.AdministratorUID, 4 << 30},
	} {
		b, e := ownedFile(f.p, f.uid, f.limit)
		if e != nil || hostaction.BytesDigest(b) != f.d {
			return nil, errNative
		}
	}
	profileRaw, e := ownedFile(controlConfig, in.AdministratorUID, 65536)
	if e != nil {
		return nil, e
	}
	var profile struct {
		AcknowledgementAdapterConfigPath string `json:"acknowledgementAdapterConfigPath"`
		InventoryExportRoot              string `json:"inventoryExportRoot"`
	}
	if json.Unmarshal(profileRaw, &profile) != nil || profile.AcknowledgementAdapterConfigPath != "/etc/vsk-labs/control/slack.json" || profile.InventoryExportRoot != "/var/lib/vsk-labs/control/exports" {
		return nil, errNative
	}
	slackRaw, e := ownedFile(profile.AcknowledgementAdapterConfigPath, in.AdministratorUID, 32768)
	if e != nil || hostaction.BytesDigest(slackRaw) != in.SlackProfileDigest {
		return nil, errNative
	}
	var slack struct {
		App   string `json:"appTokenReference"`
		Bot   string `json:"botTokenReference"`
		Nonce string `json:"nonceKeyReference"`
	}
	if json.Unmarshal(slackRaw, &slack) != nil {
		return nil, errNative
	}
	refs := []string{slack.App, slack.Bot, slack.Nonce}
	sort.Strings(refs)
	if !slices.Equal(refs, in.SlackCredentialNames) {
		return nil, errNative
	}
	// An old enrollment rule or drop-in could silently widen the exact grant.
	for _, p := range []string{"etc/polkit-1/rules.d/49-vsk-native-credential-restart.rules", "etc/systemd/system/vsk-labs.service.d"} {
		if _, e := os.Lstat(path.Join(n.root, p)); !os.IsNotExist(e) {
			return nil, errNative
		}
	}
	for selector, p := range controllerArtifacts {
		limit := int64(65536)
		if selector == "executable" {
			limit = 256 << 20
		}
		b, e := ownedFile(path.Join(n.root, p), 0, limit)
		if os.IsNotExist(e) && in.Preimages[selector] == "" {
			continue
		}
		if e != nil || in.Preimages[selector] == "" || hostaction.BytesDigest(b) != in.Preimages[selector] {
			return nil, errNative
		}
	}
	state, e := n.run(ctx, "/usr/bin/systemctl", []string{"show", "vsk-labs.service", "--property=ActiveState", "--value"})
	if e != nil || strings.TrimSpace(string(state)) != "inactive" {
		return nil, errNative
	}
	return files, nil
}

// InstallControllerFoundation is invoked only after the local API returned the
// exact current acknowledged one-use claim. It never opens SQLite, changes its
// ownership, stops the foreground writer or starts the new service.
func InstallControllerFoundation(ctx context.Context, in ControllerInstallInput, version string) (bool, error) {
	if os.Getuid() != 0 || os.Geteuid() != 0 || ValidateControllerInstallInput(in) != nil {
		return false, errNative
	}
	n := NewNativeRuntime(version).(*nativeRuntime)
	changed := false
	// The operator prepares these protected artifacts locally. Only ownership,
	// type and mode are inspected; plaintext bytes and secret hashes never enter
	// the request, plan, database, process arguments or result.
	for _, name := range in.SlackCredentialNames {
		p := "/etc/vsk-labs/control/credentials/" + name
		if ownedAncestors(p, in.AdministratorUID) != nil {
			return false, errNative
		}
		var st unix.Stat_t
		if unix.Lstat(p, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0777 != 0600 || st.Uid != 0 || st.Nlink != 1 {
			return false, errNative
		}
	}
	// The existing role serialization directory is a fixed root-only artifact;
	// creating it cannot confer control-database or service authority.
	if _, e := n.controllerFoundationPreflight(ctx, in); e != nil {
		return false, e
	}
	if _, e := protectedInfo(n.root, "var/lib/vsk-labs/access-rollback"); os.IsNotExist(e) {
		if _, e = protectedInfo(n.root, "var/lib/vsk-labs"); e != nil {
			return false, e
		}
		if e = os.Mkdir("/var/lib/vsk-labs/access-rollback", 0700); e != nil {
			return false, e
		}
		changed = true
	} else if e != nil {
		return false, e
	}
	err := n.withLock(ctx, func() error {
		files, e := n.controllerFoundationPreflight(ctx, in)
		if e != nil {
			return e
		}
		executable, e := os.Executable()
		if e != nil {
			return e
		}
		self, e := ownedFile(executable, in.AdministratorUID, 256<<20)
		if e != nil {
			self, e = ownedFile(executable, 0, 256<<20)
		}
		if e != nil || hostaction.BytesDigest(self) != in.ExecutableDigest {
			return errNative
		}
		files[controllerArtifacts["executable"]] = self
		polkitGID, e := controllerPolkitGID(ctx, n.run)
		if e != nil {
			return e
		}
		created, e := n.account(ctx, generated.LinuxRoleAccount{Selector: "control", UID: in.ServiceUID, GID: in.ServiceGID}, true)
		changed = changed || created
		if e != nil {
			return e
		}
		// Only the finite authority parent may be established here. Existing
		// controller config/state paths and their contents remain untouched.
		if _, e = protectedInfo(n.root, "etc/vsk-labs"); e != nil {
			return e
		}
		selectors := make([]string, 0, len(controllerArtifacts))
		for s := range controllerArtifacts {
			selectors = append(selectors, s)
		}
		sort.Strings(selectors)
		for _, s := range selectors {
			p := controllerArtifacts[s]
			limit := int64(65536)
			if s == "executable" {
				limit = 256 << 20
			}
			old, readErr := readProtected(n.root, p, limit)
			if readErr != nil && !os.IsNotExist(readErr) {
				return readErr
			}
			// Recheck immediately before each write; an unknown concurrent
			// change is never overwritten or recursively repaired.
			if readErr == nil && hostaction.BytesDigest(old) != in.Preimages[s] || os.IsNotExist(readErr) && in.Preimages[s] != "" {
				return errNative
			}
			mode, gid := os.FileMode(0640), int(in.ServiceGID)
			switch s {
			case "executable":
				mode, gid = 0755, 0
			case "unit":
				mode, gid = 0644, 0
			case "sudoers":
				mode, gid = 0440, 0
			case "polkit":
				gid = polkitGID
			}
			if !bytes.Equal(old, files[p]) {
				if e = writeControllerArtifact(ctx, n.root, p, files[p], mode, gid, s == "sudoers"); e != nil {
					return e
				}
				changed = true
			}
			fs, e := os.OpenRoot(n.root)
			if e != nil {
				return e
			}
			f, e := fs.OpenFile(p, os.O_RDONLY|unix.O_NOFOLLOW, 0)
			fs.Close()
			if e != nil {
				return e
			}
			e = f.Chown(0, gid)
			if e == nil {
				e = f.Chmod(mode)
			}
			if e == nil {
				e = f.Sync()
			}
			f.Close()
			if e != nil {
				return e
			}
		}
		_, e = VerifyControllerInstallResult(ctx, in)
		return e
	})
	return changed, err
}

func writeControllerArtifact(ctx context.Context, root, p string, b []byte, mode os.FileMode, gid int, sudoers bool) error {
	if _, e := protectedInfo(root, path.Dir(p)); e != nil {
		return e
	}
	fs, e := os.OpenRoot(root)
	if e != nil {
		return e
	}
	defer fs.Close()
	tmp := p + ".vsk-controller-new"
	f, e := fs.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
	if e != nil {
		return e
	}
	defer fs.Remove(tmp)
	_, e = f.Write(b)
	if e == nil {
		e = f.Chown(0, gid)
	}
	if e == nil {
		e = f.Chmod(mode)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	if sudoers {
		// Validate the inert fixed candidate before replacing the effective rule.
		c := exec.CommandContext(ctx, "/usr/sbin/visudo", "-c", "-f", "/"+tmp)
		c.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
		if c.Run() != nil {
			return errNative
		}
	}
	if e = fs.Rename(tmp, p); e != nil {
		return e
	}
	d, e := fs.Open(path.Dir(p))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}

func controllerPolkitGID(ctx context.Context, run func(context.Context, string, []string) ([]byte, error)) (int, error) {
	b, e := run(ctx, "/usr/bin/getent", []string{"group", "polkitd"})
	if e != nil {
		return 0, errNative
	}
	f := strings.Split(strings.TrimSpace(string(b)), ":")
	if len(f) != 4 || f[0] != "polkitd" {
		return 0, errNative
	}
	id, e := strconv.ParseInt(f[2], 10, 32)
	if e != nil || id < 1 {
		return 0, errNative
	}
	return int(id), nil
}

// VerifyControllerInstallResult deliberately reports only the public foundation
// facts. The old administrator server need not read the service group's policy.
// Effective native authority and loaded/denied readers remain separate checks.
func VerifyControllerInstallResult(ctx context.Context, in ControllerInstallInput) (string, error) {
	if ValidateControllerInstallInput(in) != nil {
		return "", errInput
	}
	n := NewNativeRuntime("").(*nativeRuntime)
	machine, e := controllerMachine(n.root)
	if e != nil {
		return "", e
	}
	files, e := ControllerFoundationFiles(in, machine)
	if e != nil {
		return "", e
	}
	if _, e = n.account(ctx, generated.LinuxRoleAccount{Selector: "control", UID: in.ServiceUID, GID: in.ServiceGID, Existing: true}, false); e != nil {
		return "", e
	}
	polkitGID, e := controllerPolkitGID(ctx, n.run)
	if e != nil {
		return "", e
	}
	facts := map[string]any{"inputDigest": hostaction.Digest(in), "stage": "installed-awaiting-native-verification", "serviceUID": in.ServiceUID, "serviceGID": in.ServiceGID}
	for s, p := range controllerArtifacts {
		var st unix.Stat_t
		if unix.Lstat("/"+p, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != 0 {
			return "", errNative
		}
		mode, gid := uint32(0640), uint32(in.ServiceGID)
		switch s {
		case "executable":
			mode, gid = 0755, 0
		case "unit":
			mode, gid = 0644, 0
		case "sudoers":
			mode, gid = 0440, 0
		case "polkit":
			gid = uint32(polkitGID)
		}
		if st.Mode&0777 != mode || st.Gid != gid || s != "executable" && st.Size != int64(len(files[p])) {
			return "", errNative
		}
		facts[s] = map[string]any{"uid": st.Uid, "gid": st.Gid, "mode": st.Mode & 0777, "size": st.Size}
		if s == "unit" {
			b, e := ownedFile("/"+p, 0, 65536)
			if e != nil || !bytes.Equal(b, files[p]) {
				return "", errNative
			}
			facts["unitDigest"] = hostaction.BytesDigest(b)
		}
		if s == "executable" {
			b, e := ownedFile("/"+p, 0, 256<<20)
			if e != nil || hostaction.BytesDigest(b) != in.ExecutableDigest {
				return "", errNative
			}
			facts["executableDigest"] = in.ExecutableDigest
		}
	}
	return hostaction.Digest(facts), nil
}
