//go:build !linux

package server

import (
	"context"

	"github.com/vegastack/vegastack-labs/internal/run"
)

func composeNativeCredentialLifecycleVerifier(context.Context, string, uint32) run.CredentialLifecycleVerifier {
	return run.UnavailableCredentialLifecycleVerifier{}
}
