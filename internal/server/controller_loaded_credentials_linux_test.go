//go:build linux

package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/run"
	"testing"
)

func TestControllerCredentialScopeDriftDoesNotFallBackToRestart(t *testing.T) {
	_, _, b, _ := controllerCredentialFixture()
	// A nil native verifier would panic if revoked scope fell through to the
	// ordinary restarting verifier; this must reject before any native call.
	v := nativeLifecycleRunVerifier{loadedCredential: func(context.Context, credentialref.LifecycleBinding) bool { return false }}
	if _, err := v.Verify(context.Background(), run.ExactStepBinding{}, b); err == nil {
		t.Fatal("drifting controller scope admitted")
	}
}
