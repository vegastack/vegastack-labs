package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReviewedRecoveryUnixFileRequiresExactSource(t *testing.T) {
	for _, path := range []string{
		"internal/recovery/manifest_file_unix.go",
		"internal/recovery/receipt_file_unix.go",
		"internal/server/recovery_recipient_linux.go",
	} {
		content, err := os.ReadFile(filepath.Join("..", "..", path))
		if err != nil {
			t.Fatal(err)
		}
		if !reviewedRecoveryUnixFile(path, content) {
			t.Fatalf("reviewed recovery source rejected: %s", path)
		}
		if reviewedRecoveryUnixFile(path, append(content, []byte("\n// unreviewed source\n")...)) {
			t.Fatalf("changed recovery source retained Unix authority: %s", path)
		}
		if reviewedRecoveryUnixFile("internal/recovery/extra_unix.go", content) {
			t.Fatal("extra recovery source retained Unix authority")
		}
	}
}
