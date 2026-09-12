//go:build !linux

package server

import (
	"context"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

type systemdCredentialResolver struct{}

func newSystemdCredentialResolver(uint32) (*systemdCredentialResolver, error) {
	return nil, failure.New(generated.ErrorCodeUnsupportedPlatform, "native-credential-resolver", false)
}

func (*systemdCredentialResolver) Resolve(context.Context, credentialref.Reference) ([]byte, error) {
	return nil, failure.New(generated.ErrorCodeUnsupportedPlatform, "native-credential-resolver", false)
}
