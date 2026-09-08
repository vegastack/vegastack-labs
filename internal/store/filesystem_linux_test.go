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

func TestLocalFilesystemTypesFailClosed(t *testing.T) {
	for _, filesystemType := range []uint64{0xef53, 0x58465342, 0x9123683e, 0xf2f52010, 0x01021994, 0x2fc12fc1} {
		if !isLocalFilesystemType(filesystemType) {
			t.Fatalf("known local filesystem %x rejected", filesystemType)
		}
	}
	for _, filesystemType := range []uint64{0x6969, 0x517b, 0xff534d42, 0x65735546, 0x5346414f, 0x01021997, 0x00c36400, 0x794c7630, 0} {
		if isLocalFilesystemType(filesystemType) {
			t.Fatalf("remote, layered, or unknown filesystem %x accepted", filesystemType)
		}
	}
}
