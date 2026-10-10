//go:build !linux

package debianaccess

import "context"

func ObserveNativeRollback(context.Context, string) (NativeRollbackObservation, error) {
	return NativeRollbackObservation{}, errAccess
}
