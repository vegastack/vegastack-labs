//go:build !linux

package hostaction

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

func InspectNativeExecution(context.Context, generated.HostActionBundle) (NativeExecutionObservation, error) {
	return NativeExecutionObservation{}, blocked()
}
