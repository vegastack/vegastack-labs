package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReviewedHostDiscoveryRejectsChangedAndAddedSource(t *testing.T) {
	names := []string{"collector.go", "decode.go"}
	temporary := t.TempDir()
	for _, name := range names {
		original, err := os.ReadFile(filepath.Join("..", "..", "internal", "adapter", "hostdiscovery", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(temporary, name), original, 0600); err != nil {
			t.Fatal(err)
		}
	}
	candidate := checkedSourcePackage{sourcePackage: sourcePackage{listed: listedPackage{Dir: temporary, GoFiles: names}}}
	if !reviewedHostDiscoveryCollectorPackage(candidate) {
		t.Fatal("reviewed collector rejected")
	}
	source := filepath.Join(temporary, "collector.go")
	original, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, append(original, []byte("\n// unreviewed execution path\n")...), 0600); err != nil {
		t.Fatal(err)
	}
	if reviewedHostDiscoveryCollectorPackage(candidate) {
		t.Fatal("changed collector inherited allowance")
	}
	if err := os.WriteFile(source, original, 0600); err != nil {
		t.Fatal(err)
	}
	candidate.listed.GoFiles = append(candidate.listed.GoFiles, "extra.go")
	if reviewedHostDiscoveryCollectorPackage(candidate) {
		t.Fatal("added source inherited allowance")
	}
}
