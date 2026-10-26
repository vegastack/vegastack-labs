//go:build windows

package networkconnect

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

// Owner-only ACL verification is unavailable on this implementation; fail
// closed instead of treating ordinary file readability as secret protection.
func ReadPrivateKey(context.Context, string) ([]byte, error) {
	return nil, failure.New(generated.ErrorCodeUnsupportedPlatform, "network-private-key", false)
}
