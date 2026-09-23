//go:build linux || darwin

package recovery

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstalledPackageRejectsChangedOrUnprotectedArtifact(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	witness := filepath.Join(dir, systemSignedWitnessName)
	envelope := filepath.Join(dir, systemEnvelopeName)
	for _, file := range []string{witness, envelope} {
		if err := os.WriteFile(file, []byte("public-fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	uid := uint32(os.Geteuid())
	if _, err := readProtectedPackageFiles(dir, uid, nil); err != nil {
		t.Fatalf("protected package rejected: %v", err)
	}
	if _, err := readProtectedPackageFiles(dir, uid, func() {
		if err := os.WriteFile(witness, []byte("changed-fixtur"), 0o600); err != nil {
			t.Fatal(err)
		}
	}); err == nil {
		t.Fatal("in-place changed witness admitted")
	}
	if _, err := readProtectedPackageFiles(dir, uid, func() {
		if err := os.Rename(witness, witness+".old"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(witness, []byte("replacement"), 0o600); err != nil {
			t.Fatal(err)
		}
	}); err == nil {
		t.Fatal("replaced witness inode admitted")
	}
	if err := os.Link(envelope, envelope+".link"); err != nil {
		t.Fatal(err)
	}
	if _, err := readProtectedPackageFiles(dir, uid, nil); err == nil {
		t.Fatal("hardlinked envelope admitted")
	}
	if err := os.Remove(envelope + ".link"); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(witness, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := readProtectedPackageFiles(dir, uid, nil); err == nil {
		t.Fatal("writable witness admitted")
	}
	if err := os.Chmod(witness, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(witness); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(witness+".old", witness); err != nil {
		t.Fatal(err)
	}
	if _, err := readProtectedPackageFiles(dir, uid, nil); err == nil {
		t.Fatal("symlinked witness admitted")
	}
}

func TestInstalledPackageEnvelopeRejectsWrongRecipientAndNoncanonicalBytes(t *testing.T) {
	pin, binding, _, _ := witnessFixture(t)
	envelope, err := SealProtectedEnvelope(context.Background(), pin, binding, io.NopCloser(strings.NewReader("private-fixture-material")))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeProtectedEnvelope(raw, pin, binding); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeProtectedEnvelope(append(append([]byte(nil), raw...), ' '), pin, binding); err == nil {
		t.Fatal("noncanonical envelope admitted")
	}
	envelope.RecipientKeyID = "wrong-recipient"
	raw, err = json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeProtectedEnvelope(raw, pin, binding); err == nil {
		t.Fatal("wrong recipient admitted")
	}
}
