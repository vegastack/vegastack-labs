//go:build linux

package server

import (
	"context"
	"os"
	"runtime"

	"github.com/vegastack/vegastack-labs/internal/failure"
)

type runtimePlatformProbe struct{}

func NewRuntimePlatformProbe() PlatformProbe { return runtimePlatformProbe{} }

func (runtimePlatformProbe) Current(ctx context.Context) (Platform, error) {
	if err := ctx.Err(); err != nil {
		return Platform{}, failure.New("INTERRUPTED", "server-platform", false)
	}
	content, err := os.ReadFile("/etc/os-release")
	if err != nil || len(content) > 64*1024 {
		return Platform{}, failure.New("UNSUPPORTED_PLATFORM", "server-platform", false)
	}
	return parseOSRelease(content, runtime.GOOS, runtime.GOARCH)
}
