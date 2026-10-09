//go:build !linux

package debianaccess

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

type unavailableSourceResolver struct{}

func NewNativeSourceResolver() SourceContextResolver { return unavailableSourceResolver{} }
func (unavailableSourceResolver) WithSource(context.Context, generated.AccessProbeSource, []generated.AccessProbeTuple, func(SourceIdentity) error) error {
	return errProbe
}
