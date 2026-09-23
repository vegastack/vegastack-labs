package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLocalRetirementReviewedSurfaceStaysHumanOnly(t *testing.T) {
	directory := filepath.Join("..", "..", "internal", "adapter", "localretention")
	for name := range reviewedLocalRetentionSources {
		if _, err := os.ReadFile(filepath.Join(directory, name)); err != nil {
			t.Fatal(err)
		}
	}
	linux := checkedSourcePackage{sourcePackage: sourcePackage{listed: listedPackage{
		ImportPath: "github.com/vegastack/vegastack-labs/internal/adapter/localretention",
		Dir:        directory, GoFiles: []string{"adapter_linux.go"},
	}}}
	if !reviewedLocalRetentionPackage(linux, linux.listed.ImportPath) {
		t.Fatal("exact local-retention source was not accepted")
	}
	if reviewedLocalRetentionPackage(linux, "github.com/vegastack/vegastack-labs/internal/adapter/other") {
		t.Fatal("foreign package inherited local-retention authority")
	}
}

func TestLocalRetirementRejectsUnreviewedSource(t *testing.T) {
	directory := t.TempDir()
	source, err := os.ReadFile(filepath.Join("..", "..", "internal", "adapter", "localretention", "adapter_linux.go"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "adapter_linux.go"), append(source, []byte("\n// unreviewed authority\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	candidate := checkedSourcePackage{sourcePackage: sourcePackage{listed: listedPackage{
		ImportPath: "github.com/vegastack/vegastack-labs/internal/adapter/localretention",
		Dir:        directory, GoFiles: []string{"adapter_linux.go"},
	}}}
	if reviewedLocalRetentionPackage(candidate, candidate.listed.ImportPath) {
		t.Fatal("modified local-retention source passed reviewed closure")
	}
}
