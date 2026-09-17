package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReviewedCredentialImportLocalClientWaveRejectsChangedAndAddedSource(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		files []string
	}{
		{"linux", []string{"client.go", "credential_client.go", "gates_client.go", "listener.go", "listener_linux.go"}},
		{"unsupported", []string{"client.go", "credential_client.go", "gates_client.go", "listener.go", "listener_unsupported.go"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			temporary := t.TempDir()
			for _, name := range testCase.files {
				original, err := os.ReadFile(filepath.Join("..", "..", "internal", "localapi", name))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(temporary, name), original, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			candidate := checkedSourcePackage{sourcePackage: sourcePackage{listed: listedPackage{Dir: temporary, GoFiles: testCase.files}}}
			if !reviewedLocalAPISource(candidate) {
				t.Fatal("the exact reviewed local gate client source was not accepted")
			}
			importFile := filepath.Join(temporary, "credential_client.go")
			original, err := os.ReadFile(importFile)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(importFile, append(original, []byte("\n// unreviewed forwarding seam\n")...), 0o600); err != nil {
				t.Fatal(err)
			}
			if reviewedLocalAPISource(candidate) {
				t.Fatal("changed credential import client source inherited the reviewed wave")
			}
			if err := os.WriteFile(importFile, original, 0o600); err != nil {
				t.Fatal(err)
			}
			candidate.listed.GoFiles = append(candidate.listed.GoFiles, "bypass.go")
			if reviewedLocalAPISource(candidate) {
				t.Fatal("added credential import client source inherited the reviewed wave")
			}
		})
	}
}
