package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReviewedGateAndAuditLocalClientWavesRejectChangedAndAddedSource(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		files []string
	}{
		{"linux", []string{"audit_client.go", "client.go", "gates_client.go", "listener.go", "listener_linux.go"}},
		{"unsupported", []string{"audit_client.go", "client.go", "gates_client.go", "listener.go", "listener_unsupported.go"}},
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
				t.Fatal("the exact reviewed local gate and audit client source was not accepted")
			}
			auditFile := filepath.Join(temporary, "audit_client.go")
			original, err := os.ReadFile(auditFile)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(auditFile, append(original, []byte("\n// unreviewed forwarding seam\n")...), 0o600); err != nil {
				t.Fatal(err)
			}
			if reviewedLocalAPISource(candidate) {
				t.Fatal("changed audit client source inherited the reviewed wave")
			}
			if err := os.WriteFile(auditFile, original, 0o600); err != nil {
				t.Fatal(err)
			}
			candidate.listed.GoFiles = append(candidate.listed.GoFiles, "bypass.go")
			if reviewedLocalAPISource(candidate) {
				t.Fatal("added local client source inherited the reviewed wave")
			}
		})
	}
}
