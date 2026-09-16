//go:build linux

package nativecredential

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type recordingEncryptRunner struct {
	args       []string
	sawPrivate bool
}

func (runner *recordingEncryptRunner) Run(_ context.Context, args []string, input []byte, output string) error {
	runner.args = append([]string(nil), args...)
	runner.sawPrivate = bytes.Equal(input, []byte("synthetic-private-canary"))
	// Mimic Debian systemd-creds recreating the output under umask 022.
	if err := os.Remove(output); err != nil {
		return err
	}
	return os.WriteFile(output, []byte("SYSTEMD-HOST-ENVELOPE-FIXTURE"), 0o644)
}

func TestNativeStageUsesHostKeyAndNeverPassesMaterialInArgs(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, "host-key")
	if err := os.WriteFile(key, bytes.Repeat([]byte{7}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &recordingEncryptRunner{}
	request := StageRequest{Name: "consumer-a-ref-a-version-a", CiphertextDirectory: dir, ExpectedUID: uint32(os.Geteuid()), HostKeyPath: key}
	digest, err := stageEncryptedWithRunner(context.Background(), strings.NewReader("synthetic-private-canary"), request, runner)
	if err != nil || digest == "" {
		t.Fatalf("stage failed: %v", err)
	}
	if !runner.sawPrivate {
		t.Fatal("private stdin not bounded and delivered")
	}
	joined := strings.Join(runner.args, " ")
	if strings.Contains(joined, "synthetic-private-canary") || !strings.Contains(joined, "--with-key=host") || !strings.Contains(joined, "--name="+request.Name) {
		t.Fatalf("unsafe argument class: %v", runner.args)
	}
	if mode := mustMode(t, filepath.Join(dir, request.Name)); mode&0o077 != 0 {
		t.Fatalf("ciphertext file exposed: %o", mode)
	}
	if _, err := stageEncryptedWithRunner(context.Background(), strings.NewReader("synthetic-private-canary"), StageRequest{Name: request.Name, CiphertextDirectory: dir, ExpectedUID: request.ExpectedUID, HostKeyPath: filepath.Join(dir, "missing")}, runner); err == nil {
		t.Fatal("missing host key accepted")
	}
}

func mustMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode()
}

func TestSystemdHostKeyRoundtripInDisposableLinuxFixture(t *testing.T) {
	if os.Getenv("VSK_NATIVE_CREDENTIAL_ROUNDTRIP") != "1" {
		t.Skip("run only in disposable Linux image with pre-created systemd host key")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	request := StageRequest{Name: "consumer-a-ref-a-version-a", CiphertextDirectory: dir, ExpectedUID: uint32(os.Geteuid())}
	canary := []byte("synthetic-private-canary")
	defer wipe(canary)
	if _, err := StageEncrypted(context.Background(), bytes.NewReader(canary), request); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, request.Name)
	command := exec.Command(credsCommandPath, "decrypt", "--name="+request.Name, path, "-")
	command.Stderr = &bytes.Buffer{} // never render private process diagnostics
	decrypted, err := command.Output()
	if err != nil || !bytes.Equal(decrypted, canary) {
		wipe(decrypted)
		t.Fatalf("host-key roundtrip failed: %v", err)
	}
	wipe(decrypted)
	wrong := exec.Command(credsCommandPath, "decrypt", "--name=other-consumer", path, "-")
	wrong.Stdout, wrong.Stderr = &bytes.Buffer{}, &bytes.Buffer{}
	if err := wrong.Run(); err == nil {
		t.Fatal("ciphertext reused under wrong consumer name")
	}
	ciphertext, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[len(ciphertext)/2] ^= 1
	if err := os.WriteFile(path, ciphertext, 0o600); err != nil {
		t.Fatal(err)
	}
	tampered := exec.Command(credsCommandPath, "decrypt", "--name="+request.Name, path, "-")
	tampered.Stdout, tampered.Stderr = &bytes.Buffer{}, &bytes.Buffer{}
	if err := tampered.Run(); err == nil {
		t.Fatal("corrupted host-key envelope decrypted")
	}
	if _, err := StageEncrypted(context.Background(), bytes.NewReader(canary), request); err == nil {
		t.Fatal("existing ciphertext version overwritten")
	}
}
