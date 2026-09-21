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

func TestLoaderKeepsValidLocalProfileWhenRemoteBlockIsInvalid(t *testing.T) {
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
	profile.RemoteRead = enabledRemoteRead()
	profile.RemoteRead.TLSPrivateKeyPath = nil
	body, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(directory, "profile.json")
	if err := os.WriteFile(profilePath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := NewLoader(uint32(os.Geteuid())).Load(context.Background(), profilePath)
	if err != nil || loaded.SocketPath != profile.SocketPath || !loaded.RemoteRead.Enabled || loaded.RemoteRead.ConfigurationValid {
		t.Fatalf("invalid remote block disabled local profile: %#v, %v", loaded, err)
	}
}

func TestVerifyLocalBackupRejectsUnsafeRootsAndBinary(t *testing.T) {
	uid := uint32(os.Geteuid())
	// Nil backup fails closed.
	if err := VerifyLocalBackup(nil, uid); err == nil {
		t.Fatal("nil local backup accepted")
	}
	directory := t.TempDir()
	standard := filepath.Join(directory, "standard")
	critical := filepath.Join(directory, "critical")
	for _, root := range []string{standard, critical} {
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// A file that is not the pinned restic executable must be rejected by digest.
	binary := filepath.Join(directory, "restic")
	if err := os.WriteFile(binary, []byte("not-real-restic"), 0o755); err != nil {
		t.Fatal(err)
	}
	backup := &LocalBackup{StandardRoot: standard, CriticalRoot: critical, ResticBinaryPath: binary,
		SourceID: "control-database", StandardRepositoryID: "local-standard", CriticalRepositoryID: "local-critical"}
	if err := VerifyLocalBackup(backup, uid); err == nil {
		t.Fatal("non-pinned restic binary accepted")
	} else if strings.Contains(err.Error(), binary) || strings.Contains(err.Error(), standard) {
		t.Fatalf("error leaked a protected path: %v", err)
	}
	// A world-writable directory root is rejected before the binary is read.
	if err := os.Chmod(standard, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := VerifyLocalBackup(backup, uid); err == nil {
		t.Fatal("world-writable backup root accepted")
	}
	if err := os.Chmod(standard, 0o700); err != nil {
		t.Fatal(err)
	}
	// A group/other-writable restic binary is rejected on mode alone.
	if err := os.Chmod(binary, 0o757); err != nil {
		t.Fatal(err)
	}
	if err := VerifyLocalBackup(backup, uid); err == nil {
		t.Fatal("writable restic binary accepted")
	}
	// A missing binary path is rejected.
	backup.ResticBinaryPath = filepath.Join(directory, "absent")
	if err := VerifyLocalBackup(backup, uid); err == nil {
		t.Fatal("absent restic binary accepted")
	}
}
