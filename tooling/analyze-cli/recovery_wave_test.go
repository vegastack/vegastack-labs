package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReviewedRecoveryCustodianClosureRejectsSigningAndSourceDrift(t *testing.T) {
	common := []string{"artifact.go", "collector.go", "custody.go", "fence_witness.go", "manifest.go", "transport.go", "witness.go"}
	for _, platform := range []struct {
		name  string
		files []string
	}{
		{"unix", []string{"manifest_file_unix.go", "receipt_file_unix.go"}},
		{"unsupported", []string{"manifest_file_unsupported.go", "receipt_file_unsupported.go"}},
	} {
		t.Run(platform.name, func(t *testing.T) {
			directory := t.TempDir()
			names := append(append([]string(nil), common...), platform.files...)
			for _, name := range names {
				data, err := os.ReadFile(filepath.Join("..", "..", "internal", "recovery", name))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(directory, name), data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			candidate := checkedSourcePackage{sourcePackage: sourcePackage{listed: listedPackage{Dir: directory, GoFiles: names}}}
			if !reviewedRecoveryCustodianPackage(candidate) {
				t.Fatal("exact custodian recovery source was rejected")
			}
			file := filepath.Join(directory, "witness.go")
			original, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(file, append(original, []byte("\nvar unreviewedSigner = ed25519.Sign\n")...), 0o600); err != nil {
				t.Fatal(err)
			}
			if reviewedRecoveryCustodianPackage(candidate) {
				t.Fatal("additional signing source inherited custodian authority")
			}
			if err := os.WriteFile(file, original, 0o600); err != nil {
				t.Fatal(err)
			}
			candidate.listed.GoFiles = append(candidate.listed.GoFiles, "sign.go")
			if reviewedRecoveryCustodianPackage(candidate) {
				t.Fatal("added signing file inherited custodian authority")
			}
		})
	}
}
