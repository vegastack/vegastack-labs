//go:build linux

package identity

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadCloudflareAccessProfileRequiresProtectedRegularFile(t *testing.T) {
	directory := t.TempDir()
	profilePath := filepath.Join(directory, "cloudflare-access.json")
	if err := os.WriteFile(profilePath, []byte(validCloudflareProfile), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCloudflareAccessProfile(context.Background(), profilePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(profilePath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCloudflareAccessProfile(context.Background(), profilePath); err == nil || strings.Contains(err.Error(), profilePath) {
		t.Fatalf("weak profile result = %v", err)
	}
}

func TestLoadCloudflareAccessProfileRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target.json")
	if err := os.WriteFile(target, []byte(validCloudflareProfile), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "profile.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCloudflareAccessProfile(context.Background(), link); err == nil || strings.Contains(err.Error(), link) {
		t.Fatalf("symlink result = %v", err)
	}
}
