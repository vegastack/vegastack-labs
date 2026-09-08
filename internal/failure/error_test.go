package failure

import (
	"errors"
	"testing"
)

func TestErrorIsStableAndDiscoverable(t *testing.T) {
	err := New("AUTHENTICATION_REQUIRED", "local-peer", false)
	if got := err.Error(); got != "AUTHENTICATION_REQUIRED: local-peer" {
		t.Fatalf("Error() = %q", got)
	}
	wrapped := errors.Join(errors.New("outer"), err)
	got, ok := As(wrapped)
	if !ok || got.Code != "AUTHENTICATION_REQUIRED" || got.Target != "local-peer" || got.Retryable {
		t.Fatalf("As() = (%#v, %t)", got, ok)
	}
}

func TestNewDoesNotAcceptDiagnosticPayload(t *testing.T) {
	err := New("INTEGRITY_FAILURE", "server-config", false)
	if err.Code != "INTEGRITY_FAILURE" || err.Target != "server-config" {
		t.Fatalf("New() = %#v", err)
	}
}
