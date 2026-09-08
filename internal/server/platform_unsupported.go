//go:build !linux

package server

import (
	"context"
	"runtime"
)

type runtimePlatformProbe struct{}

func NewRuntimePlatformProbe() PlatformProbe { return runtimePlatformProbe{} }

func (runtimePlatformProbe) Current(context.Context) (Platform, error) {
	return Platform{OS: runtime.GOOS, Architecture: runtime.GOARCH}, nil
}
