package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReviewedCredentialImportAndAuditLocalClientWavesRejectChangedAndAddedSource(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		files []string
	}{
		{"linux", []string{"audit_client.go", "backup_client.go", "client.go", "credential_client.go", "credential_lifecycle_client.go", "gates_client.go", "listener.go", "listener_linux.go"}},
		{"unsupported", []string{"audit_client.go", "backup_client.go", "client.go", "credential_client.go", "credential_lifecycle_client.go", "gates_client.go", "listener.go", "listener_unsupported.go"}},
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
				t.Fatal("the exact reviewed local gate, credential import, and audit client source was not accepted")
			}
			for _, clientFile := range []string{"audit_client.go", "credential_client.go", "credential_lifecycle_client.go"} {
				file := filepath.Join(temporary, clientFile)
				original, err := os.ReadFile(file)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(file, append(original, []byte("\n// unreviewed forwarding seam\n")...), 0o600); err != nil {
					t.Fatal(err)
				}
				if reviewedLocalAPISource(candidate) {
					t.Fatalf("changed %s source inherited the reviewed wave", clientFile)
				}
				if err := os.WriteFile(file, original, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			candidate.listed.GoFiles = append(candidate.listed.GoFiles, "bypass.go")
			if reviewedLocalAPISource(candidate) {
				t.Fatal("added local client source inherited the reviewed wave")
			}
		})
	}
}
