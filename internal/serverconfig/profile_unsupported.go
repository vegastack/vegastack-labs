//go:build !linux

package serverconfig

import (
	"context"

	"github.com/vegastack/vegastack-labs/internal/failure"
)

type unsupportedLoader struct{}

func NewLoader(uint32) Loader {
	return unsupportedLoader{}
}

func (unsupportedLoader) Load(context.Context, string) (Profile, error) {
	return Profile{}, failure.New("UNSUPPORTED_PLATFORM", "server-config", false)
}
