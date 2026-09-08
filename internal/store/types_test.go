package store

import (
	"errors"
	"strings"
	"testing"
)

func TestStoreErrorIsStableAndSanitized(t *testing.T) {
	t.Parallel()

	err := newStoreError("INTEGRITY_FAILURE", "database", false, errors.New("/private/control.db: SELECT secret_value"))
	if Code(err) != "INTEGRITY_FAILURE" {
		t.Fatalf("Code() = %q", Code(err))
	}
	for _, forbidden := range []string{"/private", "control.db", "SELECT", "secret_value"} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("Error() leaked %q: %q", forbidden, err.Error())
		}
	}
}

func TestStoreContractDefaultsAreClosed(t *testing.T) {
	t.Parallel()

	if DatabaseReady != "ready" || DatabaseSafeMode != "safe-mode" {
		t.Fatalf("database modes = %q, %q", DatabaseReady, DatabaseSafeMode)
	}
	if IntegrityUnknown != "unknown" || IntegrityVerified != "verified" || IntegrityFailed != "failed" {
		t.Fatalf("integrity states = %q, %q, %q", IntegrityUnknown, IntegrityVerified, IntegrityFailed)
	}
	if OpenExisting == InitializeNew {
		t.Fatal("open modes must be distinct")
	}
}
