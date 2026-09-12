//go:build !linux

package server

import (
	"io"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

func openProtectedSlackAcknowledgementProfile(string, uint32) (io.ReadCloser, error) {
	return nil, failure.New(generated.ErrorCodeUnsupportedPlatform, "acknowledgement-adapter-config", false)
}
