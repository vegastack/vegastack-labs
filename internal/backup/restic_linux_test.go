//go:build linux

package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
)

func buildFakeRestic(t *testing.T) (path, digest string) {
	t.Helper()
	output := filepath.Join(t.TempDir(), "fake-restic")
	build := exec.Command("go", "build", "-o", output, "./testdata/fake-restic")
	build.Env = os.Environ()
	if combined, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fake restic: %v\n%s", err, combined)
	}
	if err := os.Chmod(output, 0o700); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	return output, hex.EncodeToString(sum[:])
}

func TestResticUsesSealedPasswordFDWithoutLeak(t *testing.T) {
	binary, digest := buildFakeRestic(t)
	canary := []byte("issue-106-password-canary")
	value, err := credentialref.NewValue(canary)
	if err != nil {
		t.Fatal(err)
	}
	defer value.Close()

	runner := NewResticRunnerForTest(digest, time.Now)
	snapshot := filepath.Join(t.TempDir(), "snapshot.sqlite")
	if err := os.WriteFile(snapshot, []byte("db"), 0o600); err != nil {
		t.Fatal(err)
	}
	request := ResticRequest{
		BinaryPath: binary, Architecture: runtime.GOARCH,
		RepositoryURL: "http+unix://%2Ftmp%2Frest.sock:/repo-a/", RepositoryID: "repo-a", RepositoryClass: "standard",
		SnapshotPath: snapshot, PolicyDigest: "sha256:" + strings.Repeat("a", 64),
	}
	got, err := runner.Run(context.Background(), request, value)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if got.RepositoryFormat != 2 || got.SnapshotCount != 1 || got.ObjectCount == 0 {
		t.Fatalf("result = %#v", got)
	}
	observation := runner.Observation()
	joined := strings.Join(append(append([]string(nil), observation.Argv...), observation.Env...), "\x00") + observation.Stdout + observation.Stderr
	if strings.Contains(joined, string(canary)) {
		t.Fatal("password canary escaped through argv/env/stdout/stderr")
	}
	if observation.PasswordFileMode != "sealed-memfd" || observation.TempFileFound {
		t.Fatalf("observation = %#v", observation)
	}
	if len(observation.Env) != 0 {
		t.Fatalf("child environment was not empty: %v", observation.Env)
	}
}

func TestResticRejectsBinaryDigestMismatch(t *testing.T) {
	binary, _ := buildFakeRestic(t)
	value, err := credentialref.NewValue([]byte("canary"))
	if err != nil {
		t.Fatal(err)
	}
	defer value.Close()
	runner := NewResticRunnerForTest("0000000000000000000000000000000000000000000000000000000000000000", time.Now)
	snapshot := filepath.Join(t.TempDir(), "snapshot.sqlite")
	_ = os.WriteFile(snapshot, []byte("db"), 0o600)
	if _, err := runner.Run(context.Background(), ResticRequest{BinaryPath: binary, Architecture: runtime.GOARCH, RepositoryURL: "http+unix://x:/repo-a/", SnapshotPath: snapshot}, value); err == nil {
		t.Fatal("digest mismatch accepted")
	}
}

func TestResticExecutesVerifiedInodeAfterAtomicPathSwap(t *testing.T) {
	binary, digest := buildFakeRestic(t)
	marker := filepath.Join(t.TempDir(), "replacement-executed")
	replacement := filepath.Join(t.TempDir(), "replacement")
	if err := os.WriteFile(replacement, []byte("#!/bin/sh\nprintf replaced > '"+marker+"'\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	value, err := credentialref.NewValue([]byte("path-swap-canary"))
	if err != nil {
		t.Fatal(err)
	}
	defer value.Close()
	runner := NewResticRunnerForTest(digest, time.Now).(*resticRunner)
	runner.afterVerify = func() {
		if err := os.Rename(binary, binary+".verified"); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(replacement, binary); err != nil {
			t.Fatal(err)
		}
	}
	snapshot := filepath.Join(t.TempDir(), "snapshot.sqlite")
	if err := os.WriteFile(snapshot, []byte("db"), 0o600); err != nil {
		t.Fatal(err)
	}
	request := ResticRequest{BinaryPath: binary, Architecture: runtime.GOARCH,
		RepositoryURL: "http+unix://%2Ftmp%2Frest.sock:/repo-a/", RepositoryID: "repo-a", RepositoryClass: "standard",
		SnapshotPath: snapshot, PolicyDigest: "sha256:" + strings.Repeat("a", 64)}
	if _, err := runner.Run(context.Background(), request, value); err != nil {
		t.Fatalf("verified inode was not executed: %v", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("replacement binary executed: %v", err)
	}
}
