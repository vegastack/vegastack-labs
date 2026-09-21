//go:build linux

package server

import (
	"context"
	"os"
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

func TestDisposableNativeVerifierComposition(t *testing.T) {
	if os.Getenv("VSK141_DISPOSABLE") != "1" {
		t.Skip("requires disposable native systemd fixture")
	}
	if os.Geteuid() != 21141 {
		t.Fatal("native composition must run unprivileged")
	}
	databasePath := filepath.Join(filepath.Dir(os.Getenv("VSK141_CIPHERTEXT_ROOT")), "control.db")
	verifier := composeNativeCredentialLifecycleVerifier(context.Background(), databasePath, 21141)
	if _, unavailable := verifier.(run.UnavailableCredentialLifecycleVerifier); unavailable {
		t.Fatal("qualified local native authority did not compose")
	}
}
