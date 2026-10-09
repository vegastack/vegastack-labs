//go:build linux || darwin

package debianbaseline

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNativePolicyWritesRefuseLinksAndUnprotectedParents(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "etc/vsk-labs/baseline")
	if e := os.MkdirAll(dir, 0700); e != nil {
		t.Fatal(e)
	}
	p := "etc/vsk-labs/baseline/aide.conf"
	if e := protectedWrite(root, p, []byte("approved")); e != nil {
		t.Fatal(e)
	}
	b, e := protectedRead(root, p, 100)
	if e != nil || string(b) != "approved" {
		t.Fatal(e)
	}
	os.Remove(filepath.Join(root, p))
	os.Symlink("outside", filepath.Join(root, p))
	if e := protectedWrite(root, p, []byte("bad")); e == nil {
		t.Fatal("symlink overwritten")
	}
	os.Remove(filepath.Join(root, p))
	os.Chmod(dir, 0777)
	if e := protectedWrite(root, p, []byte("bad")); e == nil {
		t.Fatal("writable parent accepted")
	}
}
func TestNativePolicyReadRejectsHardlink(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "a"), []byte("private"), 0600)
	os.Link(filepath.Join(root, "a"), filepath.Join(root, "b"))
	if _, e := protectedRead(root, "b", 100); e == nil {
		t.Fatal("hardlink accepted")
	}
}
