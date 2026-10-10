//go:build !linux

package qualification

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

func LoadServerScope(context.Context) (generated.QualificationScope, error) {
	return generated.QualificationScope{}, failure.New(generated.ErrorCodeUnsupportedPlatform, "qualification-native", false)
}
func ExecuteStep(context.Context, serverconfig.Profile, generated.NativeStepRequest) (generated.NativeStepResult, error) {
	return generated.NativeStepResult{}, failure.New(generated.ErrorCodeUnsupportedPlatform, "qualification-native", false)
}
func OpenNativeObserver(context.Context, generated.QualificationScope) (NativeObserver, error) {
	return nil, failure.New(generated.ErrorCodeUnsupportedPlatform, "qualification-native", false)
}
func RunNative(context.Context, generated.QualificationScope) (generated.NativeReport, error) {
	return generated.NativeReport{}, failure.New(generated.ErrorCodeUnsupportedPlatform, "qualification-native", false)
}
