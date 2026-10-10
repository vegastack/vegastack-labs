//go:build !linux

package debianaccess

import (
	"context"
	"errors"
)

func revokeManagedAutomationSessions(context.Context, int64) (bool, error) {
	return false, errors.New("managed automation session revocation unavailable")
}
