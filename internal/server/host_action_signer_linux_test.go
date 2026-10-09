//go:build linux

package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestHostActionProtectedSignerRejectsReplacementAndPermissions(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("protected action signer belongs to a non-root service user")
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "action.key")
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(key)), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := newProtectedActionSigner(context.Background(), path, "action-key", uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("synthetic signed message")
	signature, err := s.Sign(context.Background(), msg)
	if err != nil || !ed25519.Verify(s.PublicKey(), msg, signature) {
		t.Fatalf("sign: %v", err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sign(context.Background(), msg); err == nil {
		t.Fatal("readable key accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(other)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sign(context.Background(), msg); err == nil {
		t.Fatal("unapproved signer replacement accepted")
	}
	link := filepath.Join(filepath.Dir(path), "linked.key")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := newProtectedActionSigner(context.Background(), link, "action-key", uint32(os.Getuid())); err == nil {
		t.Fatal("symlink key accepted")
	}
}
