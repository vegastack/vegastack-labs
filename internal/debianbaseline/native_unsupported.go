//go:build !linux && !darwin

package debianbaseline

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

type unsupportedRuntime struct{}

func NewNativeRuntime(string) Runtime { return unsupportedRuntime{} }
func (unsupportedRuntime) Inspect(context.Context, generated.HostActionBundle, generated.DebianBaselineInput) error {
	return errBaseline
}
func (unsupportedRuntime) Apply(context.Context, generated.HostActionBundle, generated.DebianBaselineInput) (Result, error) {
	return Result{}, errBaseline
}
func (unsupportedRuntime) Collect(context.Context, generated.HostActionBundle, generated.DebianBaselineInput) (Result, error) {
	return Result{}, errBaseline
}
