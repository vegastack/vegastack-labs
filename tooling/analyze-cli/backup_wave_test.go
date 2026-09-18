package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBackupProcessIsExactReviewedSurface confirms the pinned restic child source
// stays inside the reviewed backup-process closure and never reintroduces an
// environment-carried password, a password-command helper or a disabled lock.
func TestBackupProcessIsExactReviewedSurface(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "internal", "backup", "restic_linux.go"))
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
		ImportPath: "github.com/vegastack/vegastack-labs/internal/backup",
		Dir:        filepath.Join("..", "..", "internal", "backup"),
		GoFiles:    []string{"restic_linux.go"},
	}}}
	if !reviewedBackupProcessPackage(candidate, "github.com/vegastack/vegastack-labs/internal/backup") {
		t.Fatal("the exact reviewed backup process package was not accepted")
	}
	if reviewedBackupProcessPackage(candidate, "github.com/vegastack/vegastack-labs/internal/other") {
		t.Fatal("a non-backup import path inherited the reviewed os/exec allowance")
	}
}
