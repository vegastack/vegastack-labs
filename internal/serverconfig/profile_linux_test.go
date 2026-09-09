//go:build linux

package serverconfig

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoaderRequiresExistingProtectedInventoryExportRoot(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	profile := validGeneratedProfile()
	profile.SocketOwnerUID = int64(os.Geteuid())
	profile.InventoryExportRoot = filepath.Join(directory, "exports")
	if err := os.Mkdir(profile.InventoryExportRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "profile.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := NewLoader(uint32(os.Geteuid())).Load(context.Background(), path)
	if err != nil || got.InventoryExportRoot != profile.InventoryExportRoot {
		t.Fatalf("profile = %#v, %v", got, err)
	}
	if err := os.Chmod(profile.InventoryExportRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := NewLoader(uint32(os.Geteuid())).Load(context.Background(), path); err == nil || strings.Contains(err.Error(), profile.InventoryExportRoot) {
		t.Fatalf("weak root result = %v", err)
	}
}

func TestLoaderRejectsSymlinkWithoutReadingTarget(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target.json")
	if err := os.WriteFile(target, []byte("private-principal-canary"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "profile.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	_, err := NewLoader(uint32(os.Geteuid())).Load(context.Background(), link)
	if err == nil {
		t.Fatal("Load() accepted a symlink")
	}
	if strings.Contains(err.Error(), "private-principal-canary") || strings.Contains(err.Error(), link) {
		t.Fatalf("Load() leaked target content or path: %v", err)
	}
}
