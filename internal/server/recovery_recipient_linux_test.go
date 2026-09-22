//go:build linux

package server

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestSystemdRecoveryRecipientKeySourceRequiresProtectedExactFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "recovery-recipient-x25519-v1")
	if err := os.WriteFile(path, make([]byte, 32), 0o400); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	source := systemdRecoveryRecipientKeySource{ownerUID: uint32(os.Geteuid())}
	reader, err := source.OpenPrivate(context.Background(), "recipient-1")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(reader)
	_ = reader.Close()
	if err != nil || len(raw) != 32 {
		t.Fatal("protected key not read")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if reader, err := source.OpenPrivate(context.Background(), "recipient-1"); err == nil {
		_ = reader.Close()
		t.Fatal("weak key mode accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(dir, "foreign")
	if err := os.WriteFile(foreign, make([]byte, 32), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(foreign, path); err != nil {
		t.Fatal(err)
	}
	if reader, err := source.OpenPrivate(context.Background(), "recipient-1"); err == nil {
		_ = reader.Close()
		t.Fatal("symlink key accepted")
	}
}
