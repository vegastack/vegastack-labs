//go:build linux

package qualification

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProtectedSlotRefusesLinksPermissionsAndOversize(t *testing.T) {
	dir := t.TempDir()
	original := filepath.Join(dir, "original")
	if err := os.WriteFile(original, []byte("private prepared slot"), 0600); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Geteuid())
	if raw, err := ownedFile(original, uid, 64); err != nil || string(raw) != "private prepared slot" {
		t.Fatal("exact owned slot refused", err)
	}
	symlink := filepath.Join(dir, "symlink")
	if err := os.Symlink(original, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := ownedFile(symlink, uid, 64); err == nil {
		t.Fatal("symlink accepted")
	}
	hardlink := filepath.Join(dir, "hardlink")
	if err := os.Link(original, hardlink); err != nil {
		t.Fatal(err)
	}
	if _, err := ownedFile(original, uid, 64); err == nil {
		t.Fatal("multiply linked slot accepted")
	}
	if err := os.Remove(hardlink); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(original, 0640); err != nil {
		t.Fatal(err)
	}
	if _, err := ownedFile(original, uid, 64); err == nil {
		t.Fatal("shared slot accepted")
	}
	if err := os.Chmod(original, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ownedFile(original, uid, 2); err == nil {
		t.Fatal("oversize slot accepted")
	}
	raw, err := os.ReadFile(original)
	if err != nil || string(raw) != "private prepared slot" {
		t.Fatal("refusal mutated slot")
	}
}
