//go:build linux

package nativecredential

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestReadBoundedPrivateUsesCallerOwnedBufferAndRejectsOverflow(t *testing.T) {
	var owned [5]byte
	n, err := readBoundedPrivate(strings.NewReader("four"), owned[:], 1, 4)
	if err != nil || n != 4 || string(owned[:n]) != "four" {
		t.Fatalf("bounded private read = %d, %v", n, err)
	}
	wipe(owned[:])
	if owned != [5]byte{} {
		t.Fatal("caller could not wipe the complete private buffer")
	}
	if _, err := readBoundedPrivate(strings.NewReader("fifth"), owned[:], 1, 4); err == nil {
		t.Fatal("private input over the exact bound was accepted")
	}
	if _, err := readBoundedPrivate(strings.NewReader(""), owned[:], 1, 4); err == nil {
		t.Fatal("empty private input was accepted")
	}
}

func TestVerifyRecoveredDraftRequiresExactCiphertextAndIndependentBytes(t *testing.T) {
	if os.Getenv("VSK_NATIVE_CREDENTIAL_RECOVERY") != "1" {
		t.Skip("disposable Linux systemd host-key fixture")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil || os.Geteuid() != 0 {
		t.Fatal("host-key fixture may run only as root in disposable Docker")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	canary := []byte("synthetic-independent-custody-canary")
	defer wipe(canary)
	old := StageRequest{Name: "credential-old-recovery-version", CiphertextDirectory: dir, ExpectedUID: 0}
	oldFingerprint, err := StageEncrypted(context.Background(), bytes.NewReader(canary), old)
	if err != nil {
		t.Fatal(err)
	}
	retainedKey := hostKeyPath + ".vsk-144-disposable-old"
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
	oldRequest := VerifyRecoveryRequest{Name: old.Name, CiphertextDirectory: dir, ExpectedUID: 0, ExpectedFingerprint: oldFingerprint}
	if _, err := VerifyRecoveredDraft(context.Background(), oldRequest, io.NopCloser(bytes.NewReader(canary))); err == nil {
		t.Fatal("former-host ciphertext decrypted under replacement host key")
	}
	name := "credential-new-recovery-version"
	fingerprint, err := StageEncrypted(context.Background(), bytes.NewReader(canary), StageRequest{Name: name, CiphertextDirectory: dir, ExpectedUID: 0})
	if err != nil {
		t.Fatal(err)
	}
	request := VerifyRecoveryRequest{Name: name, CiphertextDirectory: dir, ExpectedUID: 0, ExpectedFingerprint: fingerprint}
	result, err := VerifyRecoveredDraft(context.Background(), request, io.NopCloser(bytes.NewReader(canary)))
	keyBytes, keyErr := os.ReadFile(hostKeyPath)
	if keyErr != nil {
		t.Fatal(keyErr)
	}
	keySum := sha256.Sum256(keyBytes)
	wipe(keyBytes)
	if err != nil || result.CiphertextFingerprint != fingerprint || result.HostKeyDigest != "sha256:"+hex.EncodeToString(keySum[:]) {
		t.Fatalf("exact replacement-host draft did not verify: %v", err)
	}
	for label, changed := range map[string]VerifyRecoveryRequest{
		"fingerprint": {Name: name, CiphertextDirectory: dir, ExpectedUID: 0, ExpectedFingerprint: oldFingerprint},
		"name":        {Name: old.Name, CiphertextDirectory: dir, ExpectedUID: 0, ExpectedFingerprint: fingerprint},
	} {
		if _, err := VerifyRecoveredDraft(context.Background(), changed, io.NopCloser(bytes.NewReader(canary))); err == nil || strings.Contains(err.Error(), string(canary)) {
			t.Fatalf("%s accepted or leaked private bytes", label)
		}
	}
	if _, err := VerifyRecoveredDraft(context.Background(), request, io.NopCloser(bytes.NewReader([]byte("wrong-independent-custody-material")))); err == nil || strings.Contains(err.Error(), string(canary)) {
		t.Fatal("wrong independent material accepted or leaked")
	}
	if _, err := VerifyRecoveredDraft(context.Background(), request, panicCustodyReader{}); err == nil || strings.Contains(err.Error(), string(canary)) {
		t.Fatal("custody reader panic accepted or leaked")
	}
	blocked := &blockingCustodyReader{started: make(chan struct{}), closed: make(chan struct{})}
	blockedContext, cancelBlocked := context.WithCancel(context.Background())
	blockedResult := make(chan error, 1)
	go func() {
		_, verifyErr := VerifyRecoveredDraft(blockedContext, request, blocked)
		blockedResult <- verifyErr
	}()
	select {
	case <-blocked.started:
	case <-time.After(2 * time.Second):
		t.Fatal("custody reader did not start")
	}
	cancelBlocked()
	select {
	case verifyErr := <-blockedResult:
		if verifyErr == nil || strings.Contains(verifyErr.Error(), string(canary)) {
			t.Fatal("cancelled custody read accepted or leaked")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled custody read did not close")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := VerifyRecoveredDraft(ctx, request, io.NopCloser(bytes.NewReader(canary))); err == nil {
		t.Fatal("cancelled recovery verified")
	}
	path := filepath.Join(dir, name)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRecoveredDraft(context.Background(), request, io.NopCloser(bytes.NewReader(canary))); err == nil {
		t.Fatal("weak ciphertext permissions accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 12345, 12345); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRecoveredDraft(context.Background(), request, io.NopCloser(bytes.NewReader(canary))); err == nil {
		t.Fatal("foreign ciphertext owner accepted")
	}
	if err := os.Chown(path, 0, 0); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "credential-link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	request.Name = "credential-link"
	if _, err := VerifyRecoveredDraft(context.Background(), request, io.NopCloser(bytes.NewReader(canary))); err == nil {
		t.Fatal("symlink ciphertext accepted")
	}
	request.Name = name
	hardlink := filepath.Join(dir, "credential-hardlink")
	if err := os.Link(path, hardlink); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRecoveredDraft(context.Background(), request, io.NopCloser(bytes.NewReader(canary))); err == nil {
		t.Fatal("hardlinked ciphertext accepted")
	}
}

type panicCustodyReader struct{}

func (panicCustodyReader) Read([]byte) (int, error) {
	panic("synthetic-independent-custody-canary")
}

func (panicCustodyReader) Close() error { return nil }

type blockingCustodyReader struct {
	started, closed      chan struct{}
	startOnce, closeOnce sync.Once
}

func (reader *blockingCustodyReader) Read([]byte) (int, error) {
	reader.startOnce.Do(func() { close(reader.started) })
	<-reader.closed
	return 0, os.ErrClosed
}

func (reader *blockingCustodyReader) Close() error {
	reader.closeOnce.Do(func() { close(reader.closed) })
	return nil
}
