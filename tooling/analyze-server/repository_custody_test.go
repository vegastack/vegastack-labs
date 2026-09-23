package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRepositoryCustodyClosureRejectsDirectControllerPath(t *testing.T) {
	root := filepath.Join("..", "..")
	for _, name := range []string{"adapter.go", "verify.go"} {
		source, err := os.ReadFile(filepath.Join(root, "internal", "adapter", "localbackup", name))
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"backup.NewRESTServer", "backup.NewVerifierRESTServer", "enumerateRepository(root", "os.ReadDir(root"} {
			if strings.Contains(string(source), forbidden) {
				t.Fatalf("%s retains direct repository authority %q", name, forbidden)
			}
		}
	}
	result, err := analyze(root)
	if err != nil {
		t.Fatal(err)
	}
	if result.RepositoryCustodyInvalid {
		t.Fatal("reviewed writer/verifier custody markers are incomplete")
	}
}
