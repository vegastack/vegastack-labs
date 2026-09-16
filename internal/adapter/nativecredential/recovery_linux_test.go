//go:build linux

package nativecredential

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCleanHostCannotUseOldHostCiphertextWithoutIndependentReencryption(t *testing.T) {
	if os.Getenv("VSK_NATIVE_CREDENTIAL_RECOVERY") != "1" {
		t.Skip("isolated, opt-in host-key recovery fixture")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil || os.Geteuid() != 0 {
		t.Fatal("host-key fixture may run only as root in disposable Docker")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	canary := []byte("synthetic-recovery-canary")
	defer wipe(canary)
	old := StageRequest{Name: "credential-old-host-version", CiphertextDirectory: dir, ExpectedUID: 0}
	if _, err := StageEncrypted(context.Background(), bytes.NewReader(canary), old); err != nil {
		t.Fatal(err)
	}
	oldCiphertext := filepath.Join(dir, old.Name)
	retainedKey := hostKeyPath + ".vsk-disposable-fixture-old"
	if _, err := os.Lstat(retainedKey); !os.IsNotExist(err) {
		t.Fatal("fixture key sibling already exists")
	}
	if err := os.Rename(hostKeyPath, retainedKey); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Remove(hostKeyPath)
		if err := os.Rename(retainedKey, hostKeyPath); err != nil {
			t.Error(err)
		}
	})
	setup := exec.Command(credsCommandPath, "setup")
	setup.Stdout, setup.Stderr = &bytes.Buffer{}, &bytes.Buffer{}
	if err := setup.Run(); err != nil {
		t.Fatalf("new disposable host key not created: %v", err)
	}
	oldDecrypt := exec.Command(credsCommandPath, "decrypt", "--name="+old.Name, oldCiphertext, "-")
	oldDecrypt.Stdout, oldDecrypt.Stderr = &bytes.Buffer{}, &bytes.Buffer{}
	if err := oldDecrypt.Run(); err == nil {
		t.Fatal("old host ciphertext decrypted under independent host key")
	}
	newVersion := StageRequest{Name: "credential-new-host-version", CiphertextDirectory: dir, ExpectedUID: 0}
	if _, err := StageEncrypted(context.Background(), bytes.NewReader(canary), newVersion); err != nil {
		t.Fatal(err)
	}
	newDecrypt := exec.Command(credsCommandPath, "decrypt", "--name="+newVersion.Name, filepath.Join(dir, newVersion.Name), "-")
	newDecrypt.Stderr = &bytes.Buffer{}
	decrypted, err := newDecrypt.Output()
	if err != nil || !bytes.Equal(decrypted, canary) {
		wipe(decrypted)
		t.Fatalf("independent re-encryption did not recover: %v", err)
	}
	wipe(decrypted)
}
