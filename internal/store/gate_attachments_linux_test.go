//go:build linux

package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestGateAttachmentStorePublishesByDigestWithoutReplacement(t *testing.T) {
	root := filepath.Join(t.TempDir(), "evidence")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	artifacts, err := NewGateAttachmentStore(root, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	data := []byte(`{"schema":"safe-proof-envelope","resultDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
	digest := gateDigest(data)
	if err := artifacts.Put(context.Background(), digest, data); err != nil {
		t.Fatal(err)
	}
	if err := artifacts.Put(context.Background(), digest, data); err != nil {
		t.Fatal(err)
	}
	if err := artifacts.Put(context.Background(), digest, []byte("different")); Code(err) != "INPUT_INVALID" {
		t.Fatalf("replace accepted: %v", err)
	}
	read, err := artifacts.Get(context.Background(), digest)
	if err != nil || string(read) != string(data) {
		t.Fatalf("read = %q %v", read, err)
	}
	if err := artifacts.Put(context.Background(), digest, make([]byte, (8<<20)+1)); Code(err) != "INPUT_INVALID" {
		t.Fatalf("oversize accepted: %v", err)
	}
}
