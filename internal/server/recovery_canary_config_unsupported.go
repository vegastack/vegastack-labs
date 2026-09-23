//go:build !linux

package server

import (
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

func readSystemRecoveryCanaryCapabilityConfig() (recoveryCanaryCapabilityConfig, error) {
	return recoveryCanaryCapabilityConfig{}, failure.New(generated.ErrorCodePrerequisiteBlocked, "recovery-canary-capability", false)
}
