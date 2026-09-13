package clientprofile

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLoadConstrainedSSHProfileBuildsFixedDirectArguments(t *testing.T) {
	directory := t.TempDir()
	knownHosts := filepath.Join(directory, "known hosts ; literal")
	if err := os.WriteFile(knownHosts, []byte("control-plane ssh-ed25519 synthetic\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(directory, "client profile.json")
	content := `{"schema":"vegastack-labs.dev/client-profile","schemaVersion":"1.0.0","transport":{"kind":"constrained-ssh","executable":"ssh","destination":"operator@control-plane","knownHostsPath":` + quote(knownHosts) + `}}`
	if err := os.WriteFile(profilePath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	profile, matched, err := Load(context.Background(), profilePath)
	if err != nil || !matched || profile.ConstrainedSSH == nil {
		t.Fatalf("Load() = %#v, %t, %v", profile, matched, err)
	}
	want := secureArguments(knownHosts, "operator@control-plane")
	if profile.ConstrainedSSH.Executable != "ssh" || !reflect.DeepEqual(profile.ConstrainedSSH.Arguments, want) {
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
	directory := t.TempDir()
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
			if err := os.WriteFile(profilePath, []byte(clientProfile(knownHosts)), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, matched, err := Load(context.Background(), profilePath); err == nil || !matched {
				t.Fatalf("known-hosts %s matched=%t err=%v", name, matched, err)
			}
		})
	}
}

func TestLoadRejectsHardlinkedClientProfile(t *testing.T) {
	directory := t.TempDir()
	knownHosts := filepath.Join(directory, "known-hosts")
	if err := os.WriteFile(knownHosts, []byte("host ssh-ed25519 synthetic\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, "profile-target.json")
	if err := os.WriteFile(target, []byte(clientProfile(knownHosts)), 0o600); err != nil {
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
	for name, transport := range map[string]string{
		"shell destination":    `{"kind":"constrained-ssh","executable":"ssh","destination":"operator@host;uname","knownHostsPath":"/tmp/known"}`,
		"alternate executable": `{"kind":"constrained-ssh","executable":"sh","destination":"operator@host","knownHostsPath":"/tmp/known"}`,
		"unknown field":        `{"kind":"constrained-ssh","executable":"ssh","destination":"operator@host","knownHostsPath":"/tmp/known","arguments":["uname"]}`,
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

func TestLoadRejectsReplaceableClientProfiles(t *testing.T) {
	directory := t.TempDir()
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

func clientProfile(knownHosts string) string {
	return `{"schema":"vegastack-labs.dev/client-profile","schemaVersion":"1.0.0","transport":{"kind":"constrained-ssh","executable":"ssh","destination":"operator@host","knownHostsPath":` + quote(knownHosts) + `}}`
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
