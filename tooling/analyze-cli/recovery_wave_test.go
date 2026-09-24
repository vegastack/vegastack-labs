package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReviewedRecoveryCustodianClosureRejectsSigningAndSourceDrift(t *testing.T) {
	common := []string{"artifact.go", "audit_continuity.go", "bound_canary_noop.go", "canary.go", "canary_capabilities.go", "canary_ports.go", "candidate.go", "candidate_authority.go", "collector.go", "custody.go", "fence.go", "fence_admission.go", "fence_coordinator.go", "fence_evidence.go", "fence_execution.go", "fence_witness.go", "manifest.go", "offsite_source.go", "operations.go", "qualification.go", "source.go", "source_admission.go", "source_handoff.go", "store_canary.go", "store_operations.go", "transport.go", "witness.go"}
	for _, platform := range []struct {
		name  string
		files []string
	}{
		{"unix", []string{"candidate_linux.go", "manifest_file_unix.go", "package_file_unix.go", "qualified_registry_linux.go", "receipt_file_unix.go", "source_admission_file_unix.go"}},
		{"darwin", []string{"candidate_unsupported.go", "manifest_file_unix.go", "package_file_unix.go", "qualified_registry_unsupported.go", "receipt_file_unix.go", "source_admission_file_unix.go"}},
		{"unsupported", []string{"candidate_unsupported.go", "manifest_file_unsupported.go", "package_file_unsupported.go", "qualified_registry_unsupported.go", "receipt_file_unsupported.go", "source_admission_file_unsupported.go"}},
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
