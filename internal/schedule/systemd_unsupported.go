//go:build !linux

package schedule

import (
	"errors"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

type RunnerProfile struct {
	UID                                 uint32
	PrincipalID, BinaryPath, ConfigPath string
}
type UnitSet struct {
	ServiceName, TimerName, Service, Timer, Digest string
}

func RenderSystemd(generated.ScheduledJobPolicy, RunnerProfile) (UnitSet, error) {
	return UnitSet{}, errors.New("UNSUPPORTED_PLATFORM")
}
