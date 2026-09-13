package clientprofile

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLoadConstrainedSSHProfileBuildsFixedDirectArguments(t *testing.T) {
	directory := testDirectory(t)
	executable := filepath.Join(directory, "ssh")
	if err := os.WriteFile(executable, []byte("synthetic ssh executable\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	knownHosts := filepath.Join(directory, "known hosts ; literal")
	if err := os.WriteFile(knownHosts, []byte("control-plane ssh-ed25519 synthetic\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(directory, "client profile.json")
	content := clientProfileForDestination(executable, knownHosts, "operator@control-plane")
	if err := os.WriteFile(profilePath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	profile, matched, err := Load(context.Background(), profilePath)
	if err != nil || !matched || profile.ConstrainedSSH == nil {
		t.Fatalf("Load() = %#v, %t, %v", profile, matched, err)
	}
	want := secureArguments(knownHosts, "operator@control-plane")
	if profile.ConstrainedSSH.Executable != executable || !reflect.DeepEqual(profile.ConstrainedSSH.Arguments, want) || profile.ConstrainedSSH.SSHPrincipalID != "principal.operator" || profile.ConstrainedSSH.DeviceID != "device.operator" || profile.ConstrainedSSH.RecoveryEpoch != 3 {
		t.Fatalf("remote invocation = %#v", profile.ConstrainedSSH)
	}
}

func TestLoadFallsBackForProtectedLocalServerProfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server-profile.json")
	if err := os.WriteFile(path, []byte(`{"schema":"vegastack-labs.dev/server-profile"}`), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, matched, err := Load(context.Background(), path); err != nil || matched {
		t.Fatalf("local fallback matched=%t err=%v", matched, err)
	}
}

func TestLoadRejectsUntrustedKnownHostsFiles(t *testing.T) {
	directory := testDirectory(t)
	executable := testSSHExecutable(t, directory)
	regular := filepath.Join(directory, "known-hosts")
	if err := os.WriteFile(regular, []byte("host ssh-ed25519 synthetic\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hardlink := filepath.Join(directory, "known-hosts-hardlink")
	if err := os.Link(regular, hardlink); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(directory, "known-hosts-symlink")
	if err := os.Symlink(regular, symlink); err != nil {
		t.Fatal(err)
	}
	worldReadable := filepath.Join(directory, "known-hosts-world-readable")
	if err := os.WriteFile(worldReadable, []byte("host ssh-ed25519 synthetic\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, knownHosts := range map[string]string{
		"missing":        filepath.Join(directory, "missing"),
		"directory":      directory,
		"root":           string(filepath.Separator),
		"hardlink":       hardlink,
		"symlink":        symlink,
		"world-readable": worldReadable,
	} {
		t.Run(name, func(t *testing.T) {
			profilePath := filepath.Join(directory, "profile-"+name+".json")
			if err := os.WriteFile(profilePath, []byte(clientProfile(executable, knownHosts)), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, matched, err := Load(context.Background(), profilePath); err == nil || !matched {
				t.Fatalf("known-hosts %s matched=%t err=%v", name, matched, err)
			}
		})
	}
}

func TestLoadRejectsHardlinkedClientProfile(t *testing.T) {
	directory := testDirectory(t)
	executable := testSSHExecutable(t, directory)
	knownHosts := filepath.Join(directory, "known-hosts")
	if err := os.WriteFile(knownHosts, []byte("host ssh-ed25519 synthetic\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, "profile-target.json")
	if err := os.WriteFile(target, []byte(clientProfile(executable, knownHosts)), 0o600); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(directory, "profile-linked.json")
	if err := os.Link(target, linked); err != nil {
		t.Fatal(err)
	}
	if _, matched, err := Load(context.Background(), linked); err == nil || !matched {
		t.Fatalf("hardlinked profile matched=%t err=%v", matched, err)
	}
}

func TestLoadRejectsRemoteCommandsAndUnsafeSSHOptions(t *testing.T) {
	sshPath := filepath.Join(t.TempDir(), "ssh")
	for name, transport := range map[string]string{
		"shell destination":    `{"kind":"constrained-ssh","executable":` + quote(sshPath) + `,"destination":"operator@host;uname","knownHostsPath":"/tmp/known"}`,
		"alternate executable": `{"kind":"constrained-ssh","executable":"/bin/sh","destination":"operator@host","knownHostsPath":"/tmp/known"}`,
		"unknown field":        `{"kind":"constrained-ssh","executable":` + quote(sshPath) + `,"destination":"operator@host","knownHostsPath":"/tmp/known","arguments":["uname"]}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "profile.json")
			content := `{"schema":"vegastack-labs.dev/client-profile","schemaVersion":"1.0.0","transport":` + transport + `}`
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, matched, err := Load(context.Background(), path); err == nil || !matched {
				t.Fatalf("Load() matched=%t err=%v", matched, err)
			}
		})
	}
}

func TestLoadRejectsBareAndReplaceableSSHExecutables(t *testing.T) {
	directory := testDirectory(t)
	knownHosts := filepath.Join(directory, "known-hosts")
	if err := os.WriteFile(knownHosts, []byte("host ssh-ed25519 synthetic\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	regular := filepath.Join(directory, "ssh-regular")
	if err := os.WriteFile(regular, []byte("synthetic\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	hardlink := filepath.Join(directory, "ssh")
	if err := os.Link(regular, hardlink); err != nil {
		t.Fatal(err)
	}
	symlinkTarget := filepath.Join(directory, "target", "ssh")
	if err := os.Mkdir(filepath.Dir(symlinkTarget), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(symlinkTarget, []byte("synthetic\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(directory, "linked", "ssh")
	if err := os.Mkdir(filepath.Dir(symlink), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(symlinkTarget, symlink); err != nil {
		t.Fatal(err)
	}
	worldWritable := filepath.Join(directory, "writable", "ssh")
	if err := os.Mkdir(filepath.Dir(worldWritable), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(worldWritable, []byte("synthetic\n"), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(worldWritable, 0o777); err != nil {
		t.Fatal(err)
	}
	for name, executable := range map[string]string{
		"bare path lookup": "ssh",
		"missing":          filepath.Join(directory, "missing", "ssh"),
		"directory":        directory,
		"hardlink":         hardlink,
		"symlink":          symlink,
		"world writable":   worldWritable,
	} {
		t.Run(name, func(t *testing.T) {
			profilePath := filepath.Join(directory, "executable-"+name+".json")
			if err := os.WriteFile(profilePath, []byte(clientProfile(executable, knownHosts)), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, matched, err := Load(context.Background(), profilePath); err == nil || !matched {
				t.Fatalf("executable %q matched=%t err=%v", executable, matched, err)
			}
		})
	}
}

func TestLoadRejectsReplaceableClientProfiles(t *testing.T) {
	directory := testDirectory(t)
	target := filepath.Join(directory, "target.json")
	profile := filepath.Join(directory, "profile.json")
	if err := os.WriteFile(target, []byte(`{"schema":"vegastack-labs.dev/client-profile"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, profile); err != nil {
		t.Fatal(err)
	}
	if _, matched, err := Load(context.Background(), profile); err == nil || !matched {
		t.Fatalf("symlink matched=%t err=%v", matched, err)
	}
}

func TestLoadRejectsOpenSSHExpansionTokensInTrustedPaths(t *testing.T) {
	for _, token := range []string{"%h", "${HOME}"} {
		t.Run("known-hosts-"+token, func(t *testing.T) {
			directory := testDirectory(t)
			executable := testSSHExecutable(t, directory)
			knownHosts := filepath.Join(directory, "known-hosts-"+token)
			if err := os.WriteFile(knownHosts, []byte("host ssh-ed25519 synthetic\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			profilePath := filepath.Join(directory, "profile.json")
			if err := os.WriteFile(profilePath, []byte(clientProfile(executable, knownHosts)), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, matched, err := Load(context.Background(), profilePath); err == nil || !matched {
				t.Fatalf("known-hosts token %q matched=%t err=%v", token, matched, err)
			}
		})

		t.Run("profile-"+token, func(t *testing.T) {
			directory := testDirectory(t)
			executable := testSSHExecutable(t, directory)
			knownHosts := filepath.Join(directory, "known-hosts")
			if err := os.WriteFile(knownHosts, []byte("host ssh-ed25519 synthetic\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			profilePath := filepath.Join(directory, "profile-"+token+".json")
			if err := os.WriteFile(profilePath, []byte(clientProfile(executable, knownHosts)), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, matched, err := Load(context.Background(), profilePath); err == nil || !matched {
				t.Fatalf("profile token %q matched=%t err=%v", token, matched, err)
			}
		})
	}
}

func TestLoadRejectsTrustedFilesUnderWritableParents(t *testing.T) {
	for _, target := range []string{"profile", "known-hosts", "executable"} {
		t.Run(target, func(t *testing.T) {
			directory := testDirectory(t)
			unsafeParent := filepath.Join(directory, "replaceable")
			if err := os.Mkdir(unsafeParent, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(unsafeParent, 0o777); err != nil {
				t.Fatal(err)
			}
			executable := testSSHExecutable(t, directory)
			knownHosts := filepath.Join(directory, "known-hosts")
			profilePath := filepath.Join(directory, "profile.json")
			if target == "executable" {
				executable = testSSHExecutable(t, unsafeParent)
			}
			if target == "known-hosts" {
				knownHosts = filepath.Join(unsafeParent, "known-hosts")
			}
			if target == "profile" {
				profilePath = filepath.Join(unsafeParent, "profile.json")
			}
			if err := os.WriteFile(knownHosts, []byte("host ssh-ed25519 synthetic\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(profilePath, []byte(clientProfile(executable, knownHosts)), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, matched, err := Load(context.Background(), profilePath); err == nil || !matched {
				t.Fatalf("%s under writable parent matched=%t err=%v", target, matched, err)
			}
		})
	}
}

func TestTrustedAncestorSnapshotRejectsParentReplacement(t *testing.T) {
	directory := testDirectory(t)
	parent := filepath.Join(directory, "parent")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "known-hosts")
	if err := os.WriteFile(path, []byte("host ssh-ed25519 synthetic\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot, ok := snapshotTrustedAncestors(path)
	if !ok {
		t.Fatal("trusted ancestor snapshot unexpectedly failed")
	}
	replaced := filepath.Join(directory, "parent-replaced")
	if err := os.Rename(parent, replaced); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("host ssh-ed25519 replacement\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if snapshot.stillTrusted(path) {
		t.Fatal("ancestor replacement retained trust")
	}
}

func quote(value string) string {
	result := `"`
	for _, character := range value {
		if character == '\\' || character == '"' {
			result += `\`
		}
		result += string(character)
	}
	return result + `"`
}

func clientProfile(executable, knownHosts string) string {
	return clientProfileForDestination(executable, knownHosts, "operator@host")
}

func clientProfileForDestination(executable, knownHosts, destination string) string {
	return `{"schema":"vegastack-labs.dev/client-profile","schemaVersion":"1.0.0","transport":{"kind":"constrained-ssh","executable":` + quote(executable) + `,"destination":` + quote(destination) + `,"knownHostsPath":` + quote(knownHosts) + `,"sshPrincipalId":"principal.operator","deviceId":"device.operator","recoveryEpoch":3}}`
}

func testSSHExecutable(t *testing.T, directory string) string {
	t.Helper()
	path := filepath.Join(directory, "ssh")
	if err := os.WriteFile(path, []byte("synthetic ssh executable\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func testDirectory(t *testing.T) string {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return directory
}

func secureArguments(knownHosts, destination string) []string {
	return []string{
		"-F", "none", "-T",
		"-o", "AddKeysToAgent=no",
		"-o", "BatchMode=yes",
		"-o", "CanonicalizeHostname=no",
		"-o", "CheckHostIP=yes",
		"-o", "ClearAllForwardings=yes",
		"-o", "ControlMaster=no",
		"-o", "EscapeChar=none",
		"-o", "ExitOnForwardFailure=yes",
		"-o", "ForwardAgent=no",
		"-o", "ForwardX11=no",
		"-o", "GatewayPorts=no",
		"-o", "GlobalKnownHostsFile=none",
		"-o", "HostbasedAuthentication=no",
		"-o", "IdentityAgent=none",
		"-o", "IdentitiesOnly=yes",
		"-o", "KbdInteractiveAuthentication=no",
		"-o", "PasswordAuthentication=no",
		"-o", "PermitLocalCommand=no",
		"-o", "ProxyCommand=none",
		"-o", "ProxyJump=none",
		"-o", "RemoteCommand=none",
		"-o", "RequestTTY=no",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UpdateHostKeys=no",
		"-o", "UserKnownHostsFile=" + knownHosts,
		"-o", "VerifyHostKeyDNS=no",
		destination,
	}
}
