//go:build !linux

package qualification

import "context"

func RunSlackFixturePeer(context.Context, string) error { return ErrUnavailable }
