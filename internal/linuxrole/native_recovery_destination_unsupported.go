//go:build !linux

package linuxrole

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

func InspectNativeRecoveryDestination(context.Context, generated.HostActionBundle, generated.LinuxRoleInput, int64, int64) error {
	return errInput
}

func RecheckNativeRecoveryDestination(context.Context, generated.LinuxRoleInput, int64, int64) error {
	return errInput
}
