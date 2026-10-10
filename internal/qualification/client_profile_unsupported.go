//go:build !linux

package qualification

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

func LoadStepClientProfile(context.Context, string, generated.NativeStepRequest) (serverconfig.Profile, error) {
	return serverconfig.Profile{}, ErrUnavailable
}
