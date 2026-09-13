//go:build !windows

package clientprofile

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRejectsClientProfileOwnedByAnotherUser(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing file ownership requires a privileged test process")
	}
	directory := t.TempDir()
	knownHosts := filepath.Join(directory, "known-hosts")
	if err := os.WriteFile(knownHosts, []byte("host ssh-ed25519 synthetic\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(directory, "profile.json")
	if err := os.WriteFile(profilePath, []byte(clientProfile(knownHosts)), 0o600); err != nil {
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
	directory := t.TempDir()
	knownHosts := filepath.Join(directory, "known-hosts")
	if err := os.WriteFile(knownHosts, []byte("host ssh-ed25519 synthetic\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(knownHosts, 1, -1); err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(directory, "profile.json")
	if err := os.WriteFile(profilePath, []byte(clientProfile(knownHosts)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, matched, err := Load(context.Background(), profilePath); err == nil || !matched {
		t.Fatalf("wrong-owner known-hosts matched=%t err=%v", matched, err)
	}
}
