//go:build linux || darwin

package debianaccess

import (
	"context"
	"crypto/ed25519"
	"golang.org/x/crypto/ssh"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

func retainedAdministratorFixture(t *testing.T) *nativeFixture {
	t.Helper()
	f := nativeFixtureNew(t)
	// Separate existing human identity; the automation fixture remains unchanged.
	key := retainedRuntimeKey(t, 91)
	secondKey := retainedRuntimeKey(t, 92)
	sudoJSON := strings.Replace(strings.Replace(exactSudoJSON, "automation", "admin-one", 1), "/usr/local/bin/vsk-labs host-action-once", "ALL", 1)
	a := generated.AccessAccount{Schema: generated.SchemaIDAccessAccount, SchemaVersion: "1.0.0", Name: "admin-one", UID: 1002, GID: 1002, Home: "/home/admin-one", Role: "human", PublicKeys: []string{key, secondKey}, PublicKeyDigests: []string{hostaction.BytesDigest([]byte(key)), hostaction.BytesDigest([]byte(secondKey))}, RetainedAdministrator: &generated.AccessRetainedAdministrator{Schema: "vegastack-labs.dev/access-retained-administrator", SchemaVersion: "1.0.0", Groups: []string{"admin-one", "docker", "sudo"}, SudoPolicyDigest: hostaction.BytesDigest([]byte(sudoJSON))}}
	f.input.Accounts = append(f.input.Accounts, a)
	write := func(name, text string) {
		t.Helper()
		p := filepath.Join(f.root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("etc/passwd", "root:x:0:0:root:/root:/bin/bash\nautomation:x:1001:1001::/home/automation:/bin/bash\nadmin-one:x:1002:1002::/home/admin-one:/bin/bash\n")
	write("etc/group", "root:x:0:\nautomation:x:1001:\nadmin-one:x:1002:\nsudo:x:27:admin-one\ndocker:x:990:admin-one\n")
	write("home/admin-one/.ssh/authorized_keys", key+" retained-comment\n"+secondKey+" second-key\n")
	f.n.homeOwnership = func(file *os.File) (uint32, uint32, error) {
		if strings.Contains(file.Name(), "admin-one") {
			return 1002, 1002, nil
		}
		return 1001, 1001, nil
	}
	baseRun := f.n.run
	f.n.run = func(ctx context.Context, bin string, args []string, input []byte) ([]byte, error) {
		raw, err := baseRun(ctx, bin, args, input)
		if bin == "/usr/bin/cvtsudoers" && strings.Contains(strings.Join(args, " "), "user=admin-one") {
			return []byte(sudoJSON), nil
		}
		return raw, err
	}
	return f
}

func TestRetainedAdministratorKeepsExactExistingIdentityGroupsKeys(t *testing.T) {
	f := retainedAdministratorFixture(t)
	if err := f.n.inspectAccounts(f.input); err != nil {
		t.Fatal("explicit retained identity rejected", err)
	}
	if err := f.n.inspectExistingKeys(f.input); err != nil {
		t.Fatal("retained existing key rejected", err)
	}
	if err := f.n.inspectSudo(context.Background(), f.input); err != nil {
		t.Fatal("exact retained sudo snapshot rejected", err)
	}
	if err := f.n.applyAccounts(context.Background(), f.input); err != nil {
		t.Fatal(err)
	}
	for _, event := range f.events {
		if strings.Contains(event, "useradd") || strings.Contains(event, "groupadd") {
			t.Fatal("retention created identities", event)
		}
	}
}

func TestRetainedAdministratorRejectsDriftAndNeverCreates(t *testing.T) {
	for _, mode := range []string{"missing-account", "uid", "primary", "missing-group", "added-group", "wrong-sudo", "missing-key", "extra-key", "absent-retention", "automation-retention", "declared-extra-key", "unsafe-key-mode", "canonical-home-disagree"} {
		t.Run(mode, func(t *testing.T) {
			f := retainedAdministratorFixture(t)
			a := &f.input.Accounts[1]
			edit := func(file, old, new string) {
				p := filepath.Join(f.root, file)
				b, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(strings.Replace(string(b), old, new, 1)), 0600); err != nil {
					t.Fatal(err)
				}
			}
			switch mode {
			case "missing-account":
				edit("etc/passwd", "admin-one:x:1002:1002::/home/admin-one:/bin/bash\n", "")
			case "uid":
				edit("etc/passwd", "admin-one:x:1002:", "admin-one:x:1003:")
			case "primary":
				edit("etc/group", "admin-one:x:1002:", "sudo:x:1002:")
			case "missing-group":
				edit("etc/group", "docker:x:990:admin-one", "docker:x:990:")
			case "added-group":
				edit("etc/group", "root:x:0:", "root:x:0:admin-one")
			case "wrong-sudo":
				a.RetainedAdministrator.SudoPolicyDigest = hostaction.Digest("other")
			case "missing-key":
				edit("home/admin-one/.ssh/authorized_keys", a.PublicKeys[0], "")
			case "extra-key":
				edit("home/admin-one/.ssh/authorized_keys", "retained-comment", "retained-comment\n"+retainedRuntimeKey(t, 93))
			case "declared-extra-key":
				a.PublicKeys = append(a.PublicKeys, retainedRuntimeKey(t, 94))
			case "canonical-home-disagree":
				if err := os.WriteFile(filepath.Join(f.root, "etc/vsk-labs/authorized_keys/admin-one"), []byte(a.PublicKeys[0]+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "unsafe-key-mode":
				if err := os.Chmod(filepath.Join(f.root, "home/admin-one/.ssh/authorized_keys"), 0666); err != nil {
					t.Fatal(err)
				}
			case "absent-retention":
				a.RetainedAdministrator = nil
			case "automation-retention":
				a.Role = "automation"
			}
			denied := f.n.inspectAccounts(f.input) != nil || f.n.inspectExistingKeys(f.input) != nil || f.n.inspectSudo(context.Background(), f.input) != nil
			if !denied {
				t.Fatal("retained identity drift accepted")
			}
			if mode == "missing-account" || mode == "uid" || mode == "primary" || mode == "missing-group" || mode == "added-group" || mode == "missing-key" || mode == "extra-key" || mode == "automation-retention" || mode == "wrong-sudo" || mode == "declared-extra-key" || mode == "unsafe-key-mode" || mode == "canonical-home-disagree" {
				if err := f.n.applyAccounts(context.Background(), f.input); err == nil {
					t.Fatal("apply did not recheck retained identity")
				}
				for _, event := range f.events {
					if strings.Contains(event, "useradd") || strings.Contains(event, "groupadd") {
						t.Fatal("identity mutation before rejection", event)
					}
				}
			}
		})
	}
}

func retainedRuntimeKey(t *testing.T, value byte) string {
	t.Helper()
	b := make([]byte, ed25519.PublicKeySize)
	for i := range b {
		b[i] = value
	}
	k, err := ssh.NewPublicKey(ed25519.PublicKey(b))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
}

func TestRetainedAdministratorSudoSnapshotRejectsMalformedOrUnbounded(t *testing.T) {
	for _, raw := range []string{`null`, `[]`, `{"User_Specs":[],"User_Specs":[]}`, `{"User_Specs":`, strings.Repeat(" ", 65537) + `{}`} {
		t.Run("invalid", func(t *testing.T) {
			f := retainedAdministratorFixture(t)
			f.input.Accounts[1].RetainedAdministrator.SudoPolicyDigest = hostaction.BytesDigest([]byte(raw))
			base := f.n.run
			f.n.run = func(ctx context.Context, bin string, args []string, input []byte) ([]byte, error) {
				if bin == "/usr/bin/cvtsudoers" && strings.Contains(strings.Join(args, " "), "user=admin-one") {
					return []byte(raw), nil
				}
				return base(ctx, bin, args, input)
			}
			if err := f.n.inspectSudo(context.Background(), f.input); err == nil {
				t.Fatal("invalid snapshot accepted even with matching digest")
			}
		})
	}
}

func TestRetainedAdministratorDoesNotRelaxAutomationSudo(t *testing.T) {
	f := retainedAdministratorFixture(t)
	base := f.n.run
	f.n.run = func(ctx context.Context, bin string, args []string, input []byte) ([]byte, error) {
		if bin == "/usr/bin/cvtsudoers" && strings.Contains(strings.Join(args, " "), "user=automation") {
			return []byte(strings.Replace(exactSudoJSON, "/usr/local/bin/vsk-labs host-action-once", "ALL", 1)), nil
		}
		return base(ctx, bin, args, input)
	}
	if err := f.n.inspectSudo(context.Background(), f.input); err == nil {
		t.Fatal("retention relaxed automation helper grant")
	}
}

func TestRetainedAdministratorSSHRequiresEffectiveHelperRestrictions(t *testing.T) {
	const good = "permitrootlogin no\nkbdinteractiveauthentication no\npasswordauthentication no\nauthorizedkeysfile /etc/vsk-labs/authorized_keys/%u\nauthenticationmethods publickey\npermittty no\nallowtcpforwarding no\nallowagentforwarding no\nx11forwarding no\npermittunnel no\n"
	for _, change := range []string{"", "authenticationmethods publickey", "permittty no", "allowtcpforwarding no", "allowagentforwarding no", "x11forwarding no", "permittunnel no"} {
		t.Run(change, func(t *testing.T) {
			f := nativeFixtureNew(t)
			base := f.n.run
			f.n.run = func(ctx context.Context, bin string, args []string, input []byte) ([]byte, error) {
				if bin == "/usr/sbin/sshd" && len(args) > 2 && strings.HasPrefix(args[2], "user=automation,") {
					out := good
					if change != "" {
						out = strings.Replace(out, change+"\n", "", 1)
					}
					return []byte(out), nil
				}
				return base(ctx, bin, args, input)
			}
			err := f.n.verifyEffectiveSSH(context.Background(), f.input)
			if (err == nil) != (change == "") {
				t.Fatalf("effective helper restriction %q: %v", change, err)
			}
		})
	}
}
