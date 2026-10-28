//go:build !linux

package controllerprerequisites

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

func collect(context.Context, string) generated.ControllerPrerequisitesData {
	return empty("unsupported")
}
