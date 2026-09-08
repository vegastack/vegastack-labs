//go:build linux

package serverconfig

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
