//go:build linux

package controllerprerequisites

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

func collect(ctx context.Context, expected string) generated.ControllerPrerequisitesData {
	return collectRoot(ctx, expected, "/")
}
