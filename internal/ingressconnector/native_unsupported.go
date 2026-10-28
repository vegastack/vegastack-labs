//go:build !linux

package ingressconnector

import "context"

type unavailable struct{}

func NewNativeRuntime() Runtime                                    { return unavailable{} }
func (unavailable) Install(context.Context, Input) (Result, error) { return Result{}, denied() }
