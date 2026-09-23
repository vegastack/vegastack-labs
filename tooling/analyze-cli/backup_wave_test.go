package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const backupImportPath = "github.com/vegastack/vegastack-labs/internal/backup"

// TestBackupProcessIsExactReviewedSurface confirms the pinned restic child source
// stays inside the reviewed backup-process closure and never reintroduces an
// environment-carried password, a password-command helper or a disabled lock.
func TestBackupProcessIsExactReviewedSurface(t *testing.T) {
	backupDir := filepath.Join("..", "..", "internal", "backup")
	source, err := os.ReadFile(filepath.Join(backupDir, reviewedBackupSubprocessFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range forbiddenBackupProcessPatterns {
		if strings.Contains(string(source), forbidden) {
			t.Fatalf("reviewed restic process source reintroduced forbidden pattern %q", forbidden)
		}
	}
	for _, required := range []string{"MemfdCreate", "F_ADD_SEALS", "/proc/self/fd/3", "ExtraFiles"} {
		if !strings.Contains(string(source), required) {
			t.Fatalf("reviewed restic process source is missing the sealed-FD marker %q", required)
		}
	}

	// The exact reviewed backup package accepts os/exec; a mismatched import path does not.
	candidate := checkedSourcePackage{sourcePackage: sourcePackage{listed: listedPackage{
		ImportPath: backupImportPath,
		Dir:        backupDir,
		GoFiles:    []string{reviewedBackupSubprocessFile},
	}}}
	if !reviewedBackupProcessPackage(candidate, backupImportPath) {
		t.Fatal("the exact reviewed backup process package was not accepted")
	}
	if reviewedBackupProcessPackage(candidate, "github.com/vegastack/vegastack-labs/internal/other") {
		t.Fatal("a non-backup import path inherited the reviewed os/exec allowance")
	}
}

// TestBackupProcessRejectsNewSubprocessFile proves a second file taking on an
// os/exec dependency fails the guard: the allowance is confined to the exact
// reviewed subprocess file, not the package.
func TestBackupProcessRejectsNewSubprocessFile(t *testing.T) {
	backupDir := filepath.Join("..", "..", "internal", "backup")
	reviewed, err := os.ReadFile(filepath.Join(backupDir, reviewedBackupSubprocessFile))
	if err != nil {
		t.Fatal(err)
	}
	stage := t.TempDir()
	if err := os.WriteFile(filepath.Join(stage, reviewedBackupSubprocessFile), reviewed, 0o600); err != nil {
		t.Fatal(err)
	}
	// A new, unreviewed file that imports os/exec.
	newFile := "sneaky_linux.go"
	newSource := "//go:build linux\n\npackage backup\n\nimport (\n\t\"os/exec\"\n)\n\nvar _ = exec.Command\n"
	if err := os.WriteFile(filepath.Join(stage, newFile), []byte(newSource), 0o600); err != nil {
		t.Fatal(err)
	}
	candidate := checkedSourcePackage{sourcePackage: sourcePackage{listed: listedPackage{
		ImportPath: backupImportPath, Dir: stage,
		GoFiles: []string{newFile, reviewedBackupSubprocessFile},
	}}}
	if reviewedBackupProcessPackage(candidate, backupImportPath) {
		t.Fatal("a new backup subprocess file inherited the reviewed os/exec allowance")
	}
}

// TestBackupProcessRejectsModifiedSubprocessFile proves that any edit to the
// reviewed subprocess file breaks the pinned digest until it is resealed.
func TestBackupProcessRejectsModifiedSubprocessFile(t *testing.T) {
	backupDir := filepath.Join("..", "..", "internal", "backup")
	reviewed, err := os.ReadFile(filepath.Join(backupDir, reviewedBackupSubprocessFile))
	if err != nil {
		t.Fatal(err)
	}
	stage := t.TempDir()
	// Preserve the linux build tag and os/exec import, but append a benign line so
	// the digest no longer matches the reviewed value.
	modified := append(append([]byte(nil), reviewed...), []byte("\n// unreviewed edit\n")...)
	if err := os.WriteFile(filepath.Join(stage, reviewedBackupSubprocessFile), modified, 0o600); err != nil {
		t.Fatal(err)
	}
	candidate := checkedSourcePackage{sourcePackage: sourcePackage{listed: listedPackage{
		ImportPath: backupImportPath, Dir: stage,
		GoFiles: []string{reviewedBackupSubprocessFile},
	}}}
	if reviewedBackupProcessPackage(candidate, backupImportPath) {
		t.Fatal("a modified subprocess file passed the pinned reviewed digest")
	}
}
