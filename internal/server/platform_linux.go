//go:build linux

package server

import (
	"context"
	"os"
	"runtime"

	"github.com/vegastack/vegastack-labs/internal/failure"
)

type runtimePlatformProbe struct{}

// runtimeOSReleasePath is fixed for normal builds. The Phase 3 verifier points
// its isolated test executable at a synthetic Debian release file at link time,
// allowing the real command boundary to run on hosted Linux without widening
// the production platform policy.
var runtimeOSReleasePath = "/etc/os-release"

func NewRuntimePlatformProbe() PlatformProbe { return runtimePlatformProbe{} }

func (runtimePlatformProbe) Current(ctx context.Context) (Platform, error) {
	if err := ctx.Err(); err != nil {
		return Platform{}, failure.New("INTERRUPTED", "server-platform", false)
	}
	content, err := os.ReadFile(runtimeOSReleasePath)
	if err != nil || len(content) > 64*1024 {
		return Platform{}, failure.New("UNSUPPORTED_PLATFORM", "server-platform", false)
	}
	return parseOSRelease(content, runtime.GOOS, runtime.GOARCH)
}
