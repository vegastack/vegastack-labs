package hostaction

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRendererRejectsUntrustedPackageAndExecutable(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("requires ordinary development user")
	}
	root := t.TempDir()
	file := filepath.Join(root, "ansible-playbook")
	if err := os.WriteFile(file, []byte("untrusted"), 0700); err != nil {
		t.Fatal(err)
	}
	if protectedRendererPath(file) {
		t.Fatal("user-owned renderer accepted")
	}
	if _, err := ansibleTreeDigest(root); err == nil {
		t.Fatal("user-owned collection accepted")
	}
}
