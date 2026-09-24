package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRestoreCommandClosureRejectsDirectProcessDatabaseAndEpochBypass(t *testing.T) {
	root := filepath.Join("..", "..", "internal")
	if !reviewedRestoreCLIFile(filepath.Join(root, "cli")) || !reviewedRestoreClientFile(filepath.Join(root, "localapi")) {
		t.Fatal("current typed restore command/client closure was rejected")
	}
	for _, test := range []struct{ name, packageDir, file, from, to string }{
		{"shell", "cli", "restore.go", `"fmt"`, `"fmt"\n\t"os/exec"`},
		{"direct database", "localapi", "restore_client.go", `"encoding/json"`, `"encoding/json"\n\t"database/sql"`},
		{"old epoch accepted", "localapi", "restore_client.go", "data.PriorRecoveryEpoch == result.RecoveryEpoch", "true"},
		{"new epoch unchecked", "localapi", "restore_client.go", "data.NextRecoveryEpoch == result.RecoveryEpoch", "true"},
		{"run route widened", "localapi", "restore_client.go", `"api.v1.restores.run"`, `"api.v1.restores.plan"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			source, err := os.ReadFile(filepath.Join(root, test.packageDir, test.file))
			if err != nil {
				t.Fatal(err)
			}
			changed := strings.Replace(string(source), test.from, test.to, 1)
			if changed == string(source) {
				t.Fatal("mutation did not change source")
			}
			if err := os.WriteFile(filepath.Join(directory, test.file), []byte(changed), 0o600); err != nil {
				t.Fatal(err)
			}
			accepted := reviewedRestoreCLIFile(directory)
			if test.packageDir == "localapi" {
				accepted = reviewedRestoreClientFile(directory)
			}
			if accepted {
				t.Fatal("hostile restore command/client mutation accepted")
			}
		})
	}
}
