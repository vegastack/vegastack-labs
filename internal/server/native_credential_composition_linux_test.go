//go:build linux

package server

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/run"
)

func TestNativeVerifierCompositionRejectsMissingAuthority(t *testing.T) {
	verifier := composeNativeCredentialLifecycleVerifier(context.Background(), filepath.Join(t.TempDir(), "control.db"), 1001)
	if _, unavailable := verifier.(run.UnavailableCredentialLifecycleVerifier); !unavailable {
		t.Fatal("absent installed authority registered a production verifier")
	}
}
