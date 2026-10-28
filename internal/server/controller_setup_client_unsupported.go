//go:build !linux

package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/linuxrole"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

func loadControllerSetupClientProfile(context.Context, string, uint32, uint32) (serverconfig.Profile, error) {
	return serverconfig.Profile{}, actionFailure()
}

func verifyControllerRecoveryImage(context.Context, linuxrole.ControllerInstallInput) error {
	return actionFailure()
}
