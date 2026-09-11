//go:build !linux

package identity

import (
	"io"

	"github.com/vegastack/vegastack-labs/internal/failure"
)

func openProtectedCloudflareAccessProfile(string) (io.ReadCloser, error) {
	return nil, failure.New("UNSUPPORTED_PLATFORM", "cloudflare-access-config", false)
}
