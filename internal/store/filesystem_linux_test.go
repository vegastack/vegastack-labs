//go:build linux

package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFilesystemRequiresAbsoluteCleanProtectedParent(t *testing.T) {
	inspector := newFilesystemInspector()
	uid := uint32(os.Geteuid())
	if _, err := inspector.InspectParent(context.Background(), "relative/control.db", uid); Code(err) != "INTEGRITY_FAILURE" {
		t.Fatalf("relative code = %q", Code(err))
	}
	root := t.TempDir()
	nested := filepath.Join(root, "nested")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(nested, link); err != nil {
		t.Fatal(err)
	}
	if _, err := inspector.InspectParent(context.Background(), filepath.Join(link, "control.db"), uid); Code(err) != "INTEGRITY_FAILURE" {
		t.Fatalf("component symlink code = %q", Code(err))
	}
}
