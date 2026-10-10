package qualification

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

type NativeObserver interface {
	Observe(context.Context, generated.NativeObservationBinding) (generated.NativeObservation, error)
	Close() error
}
