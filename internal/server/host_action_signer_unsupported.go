//go:build !linux

package server

import "context"

func newProtectedActionSigner(context.Context, string, string, uint32) (ActionSigner, error) {
	return nil, actionFailure()
}
