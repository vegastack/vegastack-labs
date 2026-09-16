//go:build linux

package nativecredential

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInspectEncryptedClassifiesProtectedCiphertextWithoutFollowingLinks(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	request := InspectRequest{Name: "credential-a", CiphertextDirectory: directory, ExpectedUID: uint32(os.Geteuid())}
	absent, err := InspectEncrypted(context.Background(), request)
	if err != nil || absent.State != "absent" || absent.Fingerprint != "" {
		t.Fatalf("absent=%#v err=%v", absent, err)
	}
	path := filepath.Join(directory, request.Name)
	if err := os.WriteFile(path, []byte(strings.Repeat("ciphertext", 4)), 0o600); err != nil {
		t.Fatal(err)
	}
	present, err := InspectEncrypted(context.Background(), request)
	if err != nil || present.State != "present" || !strings.HasPrefix(present.Fingerprint, "sha256:") {
		t.Fatalf("present=%#v err=%v", present, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("missing-target", path); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectEncrypted(context.Background(), request); err == nil {
		t.Fatal("ciphertext symlink accepted")
	}
}

func TestInspectEncryptedRejectsWeakDirectoryAndFileModes(t *testing.T) {
	directory := t.TempDir()
	request := InspectRequest{Name: "credential-a", CiphertextDirectory: directory, ExpectedUID: uint32(os.Geteuid())}
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectEncrypted(context.Background(), request); err == nil {
		t.Fatal("weak directory accepted")
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, request.Name), []byte(strings.Repeat("ciphertext", 4)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectEncrypted(context.Background(), request); err == nil {
		t.Fatal("weak ciphertext mode accepted")
	}
}

func TestInspectEncryptedRejectsWrongTypeSizeAndOwner(t *testing.T) {
	for _, fixture := range []struct {
		name  string
		setup func(t *testing.T, path string)
	}{
		{name: "directory", setup: func(t *testing.T, path string) {
			t.Helper()
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "short", setup: func(t *testing.T, path string) {
			t.Helper()
			if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "oversize", setup: func(t *testing.T, path string) {
			t.Helper()
			if err := os.WriteFile(path, []byte(strings.Repeat("x", 8193)), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			directory := t.TempDir()
			if err := os.Chmod(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			request := InspectRequest{Name: "credential-a", CiphertextDirectory: directory, ExpectedUID: uint32(os.Geteuid())}
			fixture.setup(t, filepath.Join(directory, request.Name))
			if _, err := InspectEncrypted(context.Background(), request); err == nil {
				t.Fatal("unsafe ciphertext accepted")
			}
		})
	}
	if os.Geteuid() == 0 {
		directory := t.TempDir()
		if err := os.Chmod(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, "credential-a")
		if err := os.WriteFile(path, []byte(strings.Repeat("ciphertext", 4)), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(path, 1, -1); err != nil {
			t.Fatal(err)
		}
		if _, err := InspectEncrypted(context.Background(), InspectRequest{Name: "credential-a", CiphertextDirectory: directory, ExpectedUID: 0}); err == nil {
			t.Fatal("wrong ciphertext owner accepted")
		}
	}
}
