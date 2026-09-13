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
	profilePath := filepath.Join(directory, "client profile.json")
	content := `{"schema":"vegastack-labs.dev/client-profile","schemaVersion":"1.0.0","transport":{"kind":"constrained-ssh","executable":"ssh","destination":"operator@control-plane","knownHostsPath":` + quote(knownHosts) + `}}`
	if err := os.WriteFile(profilePath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	profile, matched, err := Load(context.Background(), profilePath)
	if err != nil || !matched || profile.ConstrainedSSH == nil {
		t.Fatalf("Load() = %#v, %t, %v", profile, matched, err)
	}
	want := []string{"-T", "-o", "BatchMode=yes", "-o", "ClearAllForwardings=yes", "-o", "ExitOnForwardFailure=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + knownHosts, "operator@control-plane"}
	if profile.ConstrainedSSH.Executable != "ssh" || !reflect.DeepEqual(profile.ConstrainedSSH.Arguments, want) {
		t.Fatalf("remote invocation = %#v", profile.ConstrainedSSH)
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
