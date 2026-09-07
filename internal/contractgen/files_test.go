package contractgen

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/metadata"
)

func TestWriteAndCheckDetectDriftWithoutMutating(t *testing.T) {
	t.Parallel()

	artifacts, err := Generate(metadata.Current())
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := Write(root, artifacts); err != nil {
		t.Fatal(err)
	}
	if matches, err := filepath.Glob(filepath.Join(root, "**", ".contracts-*")); err != nil || len(matches) != 0 {
		t.Fatalf("temporary files after Write() = %v, %v", matches, err)
	}

	target := filepath.Join(root, filepath.FromSlash(artifacts[0].Path))
	before, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	if err := Check(root, artifacts); err != nil {
		t.Fatalf("Check() after Write() = %v", err)
	}
	after, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if !before.ModTime().Equal(after.ModTime()) {
		t.Fatalf("Check() changed mtime from %s to %s", before.ModTime(), after.ModTime())
	}

	if err := os.WriteFile(target, []byte("drift\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err = Check(root, artifacts)
	if err == nil || !strings.Contains(err.Error(), artifacts[0].Path) || !strings.Contains(err.Error(), "GENERATED_STALE") {
		t.Fatalf("Check() drift error = %v, want named stale artifact", err)
	}
	content, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !reflect.DeepEqual(content, []byte("drift\n")) {
		t.Fatalf("Check() modified stale file: %q", content)
	}

	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	err = Check(root, artifacts)
	if err == nil || !strings.Contains(err.Error(), artifacts[0].Path) || !strings.Contains(err.Error(), "GENERATED_MISSING") {
		t.Fatalf("Check() missing error = %v, want named missing artifact", err)
	}
}

func TestWriteRejectsUnsafeArtifactPaths(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	for name, artifactPath := range map[string]string{
		"absolute":  filepath.Join(string(filepath.Separator), "outside"),
		"escape":    "../outside",
		"duplicate": "safe/file",
	} {
		name, artifactPath := name, artifactPath
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			artifacts := []Artifact{{Path: artifactPath, Content: []byte("safe\n")}}
			if name == "duplicate" {
				artifacts = append(artifacts, artifacts[0])
			}
			if err := Write(root, artifacts); err == nil {
				t.Fatal("Write() error = nil")
			}
		})
	}
}

func TestWriteRejectsSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires privileges on some Windows hosts")
	}

	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	err := Write(root, []Artifact{{Path: "linked/contract.json", Content: []byte("safe\n")}})
	if err == nil || !strings.Contains(err.Error(), "GENERATED_PATH_UNSAFE") {
		t.Fatalf("Write() error = %v, want symlink escape rejection", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "contract.json")); !os.IsNotExist(err) {
		t.Fatalf("outside artifact exists or stat failed unexpectedly: %v", err)
	}
}
