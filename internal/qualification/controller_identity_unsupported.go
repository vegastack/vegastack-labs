//go:build !linux

package qualification

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

func MeasureControllerIdentity(context.Context, generated.QualificationScope, string) (generated.NativeControllerIdentity, error) {
	return generated.NativeControllerIdentity{}, ErrUnavailable
}
