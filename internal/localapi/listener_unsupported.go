//go:build !linux

package localapi

import (
	"context"

	"github.com/vegastack/vegastack-labs/internal/failure"
)

func Listen(context.Context, ListenConfig) (Listener, error) {
	return nil, failure.New("UNSUPPORTED_PLATFORM", "control-service", false)
}
