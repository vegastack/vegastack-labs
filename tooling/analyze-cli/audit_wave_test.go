package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReviewedAuditPublicVerificationRejectsChangedAndAddedSource(t *testing.T) {
	names := []string{"canonical.go", "chain.go", "checkpoint.go", "types.go", "verify.go"}
	temporary := t.TempDir()
	for _, name := range names {
		original, err := os.ReadFile(filepath.Join("..", "..", "internal", "audit", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(temporary, name), original, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	candidate := checkedSourcePackage{sourcePackage: sourcePackage{listed: listedPackage{Dir: temporary, GoFiles: names}}}
	if !reviewedAuditVerificationPackage(candidate) {
		t.Fatal("the exact reviewed public-key verification package was not accepted")
	}
	verifyFile := filepath.Join(temporary, "verify.go")
	original, err := os.ReadFile(verifyFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(verifyFile, append(original, []byte("\n// unreviewed trust seam\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if reviewedAuditVerificationPackage(candidate) {
		t.Fatal("changed audit verification source inherited the reviewed wave")
	}
	if err := os.WriteFile(verifyFile, original, 0o600); err != nil {
		t.Fatal(err)
	}
	candidate.listed.GoFiles = append(candidate.listed.GoFiles, "sign.go")
	if reviewedAuditVerificationPackage(candidate) {
		t.Fatal("added audit signing source inherited the reviewed wave")
	}
}
