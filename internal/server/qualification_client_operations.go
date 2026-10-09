package server

import (
	"context"
	"errors"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"github.com/vegastack/vegastack-labs/internal/qualification"
)

func (o *Operations) InspectQualification(ctx context.Context, path string, in generated.QualificationInspectRequest) (localapi.TypedResponse[generated.QualificationInspectData], error) {
	c, p, e := o.controlClient(ctx, path)
	if e != nil {
		return localapi.TypedResponse[generated.QualificationInspectData]{}, e
	}
	return c.InspectQualification(ctx, p, in)
}
func (o *Operations) RunNativeQualification(ctx context.Context, in generated.QualificationScope) (generated.NativeReport, error) {
	out, err := qualification.RunNative(ctx, in)
	return out, nativeOperationError(err)
}
func (o *Operations) ExecuteQualificationStep(ctx context.Context, path string, in generated.NativeStepRequest) (generated.NativeStepResult, error) {
	_, p, e := o.controlClient(ctx, path)
	if e != nil {
		return generated.NativeStepResult{}, e
	}
	out, err := qualification.ExecuteStep(ctx, p, in)
	return out, nativeOperationError(err)
}

func nativeOperationError(err error) error {
	if err == nil {
		return nil
	}
	if stable, ok := failure.As(err); ok {
		return failure.New(stable.Code, "qualification-native", stable.Retryable)
	}
	code := generated.ErrorCodePrerequisiteBlocked
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		code = generated.ErrorCodeInterrupted
	}
	return failure.New(code, "qualification-native", false)
}

func (o *Operations) RunSlackFixturePeer(ctx context.Context) error {
	if o == nil || o.build.SourceRevision == nil {
		return failure.New(generated.ErrorCodePrerequisiteBlocked, "qualification-native", false)
	}
	return nativeOperationError(qualification.RunSlackFixturePeer(ctx, *o.build.SourceRevision))
}
