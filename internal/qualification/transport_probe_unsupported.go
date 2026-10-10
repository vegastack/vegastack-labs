//go:build !linux

package qualification

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

func NativeTransportProbe(context.Context, generated.HostActionBundle) (string, error) {
	return "", nil
}
