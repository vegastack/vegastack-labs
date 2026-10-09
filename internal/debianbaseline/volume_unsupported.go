//go:build !linux

package debianbaseline

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

func ObserveVolumes(context.Context, generated.DebianBaselineInput) ([]generated.AccessMeasurement, error) {
	return nil, errVolume
}
func VerifyVolumeRecovery(context.Context, generated.VolumeRecoveryInput) ([]generated.AccessMeasurement, error) {
	return nil, errVolume
}
