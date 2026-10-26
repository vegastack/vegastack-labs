//go:build !linux

package hostingplatform

import "context"

type unsupported struct{}

func NewNativeRuntime() Runtime                                            { return unsupported{} }
func (unsupported) Execute(context.Context, string, Input) (Result, error) { return Result{}, denied() }
