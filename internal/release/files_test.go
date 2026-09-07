package release

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestOpenRelativeRejectsUnsafePortablePaths(t *testing.T) {
	root := t.TempDir()
	for _, relative := range []string{"", "/absolute", "../escape", "a/../b", "./a", "a//b", `a\b`, "a:b", "a\x00b", "NUL.txt", "trail. ", "é"} {
		t.Run(relative, func(t *testing.T) {
			_, _, err := openRelative(root, relative, nil)
			assertReleaseError(t, err, generated.ErrorCodeInputInvalid)
		})
	}
}

func TestOpenRelativeRejectsMissingSymlinkAndNonRegularFiles(t *testing.T) {
	root := t.TempDir()
	_, _, err := openRelative(root, "missing", nil)
	assertReleaseError(t, err, generated.ErrorCodePrerequisiteBlocked)

	if err := os.Mkdir(filepath.Join(root, "directory"), 0o700); err != nil {
		t.Fatal(err)
	}
	_, _, err = openRelative(root, "directory", nil)
	assertReleaseError(t, err, generated.ErrorCodeEvidenceInvalid)

	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	_, _, err = openRelative(root, "link", nil)
	assertReleaseError(t, err, generated.ErrorCodeEvidenceInvalid)
}

func TestFinishFileDetectsPathReplacement(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "asset")
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	declared := int64(5)
	file, snapshot, err := openRelative(root, "asset", &declared)
	if err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(root, "old")
	if err := os.Rename(path, old); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	assertReleaseError(t, finishFile(file, snapshot), generated.ErrorCodeEvidenceInvalid)
}

func TestOpenRelativeRejectsIntermediateSymlink(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(realDir, "asset"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realDir, filepath.Join(root, "alias")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	_, _, err := openRelative(root, "alias/asset", nil)
	assertReleaseError(t, err, generated.ErrorCodeEvidenceInvalid)
}
