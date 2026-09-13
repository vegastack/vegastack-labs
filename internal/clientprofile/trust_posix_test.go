//go:build !windows

package clientprofile

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPOSIXDirectoryTrustRejectsUnsafeOwnershipAndModes(t *testing.T) {
	current := uint32(os.Geteuid())
	for name, test := range map[string]struct {
		mode  os.FileMode
		uid   uint32
		nlink uint64
		want  bool
	}{
		"private current owner": {os.ModeDir | 0o700, current, 1, true},
		"root owned read only":  {os.ModeDir | 0o755, 0, 1, true},
		"sticky shared root":    {os.ModeDir | os.ModeSticky | 0o777, 0, 1, true},
		"world writable":        {os.ModeDir | 0o777, current, 1, false},
		"group writable":        {os.ModeDir | 0o770, current, 1, false},
		"untrusted owner":       {os.ModeDir | 0o700, current + 1, 1, false},
		"not a directory":       {0o700, current, 1, false},
		"invalid link count":    {os.ModeDir | 0o700, current, 0, false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := trustedPOSIXDirectoryMetadata(test.mode, test.uid, current, test.nlink); got != test.want {
				t.Fatalf("trustedPOSIXDirectoryMetadata() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestLoadRejectsClientProfileOwnedByAnotherUser(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing file ownership requires a privileged test process")
	}
	directory := testDirectory(t)
	executable := testSSHExecutable(t, directory)
	knownHosts := filepath.Join(directory, "known-hosts")
	if err := os.WriteFile(knownHosts, []byte("host ssh-ed25519 synthetic\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(directory, "profile.json")
	if err := os.WriteFile(profilePath, []byte(clientProfile(executable, knownHosts)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(profilePath, 1, -1); err != nil {
		t.Fatal(err)
	}
	if _, matched, err := Load(context.Background(), profilePath); err == nil || !matched {
		t.Fatalf("wrong-owner profile matched=%t err=%v", matched, err)
	}
}

func TestLoadRejectsKnownHostsOwnedByAnotherUser(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing file ownership requires a privileged test process")
	}
	directory := testDirectory(t)
	executable := testSSHExecutable(t, directory)
	knownHosts := filepath.Join(directory, "known-hosts")
	if err := os.WriteFile(knownHosts, []byte("host ssh-ed25519 synthetic\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(knownHosts, 1, -1); err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(directory, "profile.json")
	if err := os.WriteFile(profilePath, []byte(clientProfile(executable, knownHosts)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, matched, err := Load(context.Background(), profilePath); err == nil || !matched {
		t.Fatalf("wrong-owner known-hosts matched=%t err=%v", matched, err)
	}
}

func TestLoadRejectsSSHExecutableOwnedByAnotherUser(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing file ownership requires a privileged test process")
	}
	directory := testDirectory(t)
	executable := testSSHExecutable(t, directory)
	if err := os.Chown(executable, 1, -1); err != nil {
		t.Fatal(err)
	}
	knownHosts := filepath.Join(directory, "known-hosts")
	if err := os.WriteFile(knownHosts, []byte("host ssh-ed25519 synthetic\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(directory, "profile.json")
	if err := os.WriteFile(profilePath, []byte(clientProfile(executable, knownHosts)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, matched, err := Load(context.Background(), profilePath); err == nil || !matched {
		t.Fatalf("wrong-owner executable matched=%t err=%v", matched, err)
	}
}
