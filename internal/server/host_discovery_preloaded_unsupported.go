//go:build !linux

package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
)

type unsupportedDiscoveryKeyReader struct{}

func newPreloadedDiscoveryKeyReader(uint32) preloadedDiscoveryKeyReader {
	return unsupportedDiscoveryKeyReader{}
}
func (unsupportedDiscoveryKeyReader) Borrow(context.Context, hostdiscovery.Target) (*credentialref.Value, error) {
	return nil, hostdiscovery.Error(generated.ErrorCodePrerequisiteBlocked)
}
