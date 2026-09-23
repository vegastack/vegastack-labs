//go:build linux

package server

import (
	"context"
	"os"
	"path/filepath"

	"github.com/vegastack/vegastack-labs/internal/adapter/nativecredential"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

type systemdCredentialResolver struct {
	directory *os.File
	ownerUID  uint32
}

func newSystemdCredentialResolver(ownerUID uint32) (*systemdCredentialResolver, error) {
	directoryPath := os.Getenv("CREDENTIALS_DIRECTORY")
	if directoryPath == "" || !filepath.IsAbs(directoryPath) || filepath.Clean(directoryPath) != directoryPath {
		return nil, failure.New(generated.ErrorCodePrerequisiteBlocked, "native-credential-resolver", false)
	}
	directory, err := os.Open(directoryPath)
	if err != nil {
		return nil, failure.New(generated.ErrorCodePrerequisiteBlocked, "native-credential-resolver", false)
	}
	return &systemdCredentialResolver{directory: directory, ownerUID: ownerUID}, nil
}

func (resolver *systemdCredentialResolver) Resolve(ctx context.Context, reference credentialref.Reference) ([]byte, error) {
	allowedConsumer := reference.Consumer == "slack-acknowledgement" || reference.Consumer == "r2.retention.lock-admin"
	if resolver == nil || resolver.directory == nil || ctx == nil || !allowedConsumer || reference.ID == "" || filepath.Base(reference.ID) != reference.ID {
		return nil, failure.New(generated.ErrorCodeAuthorizationDenied, "native-credential-reference", false)
	}
	if err := ctx.Err(); err != nil {
		return nil, failure.New(generated.ErrorCodeInterrupted, "native-credential-resolver", false)
	}
	return nativecredential.ReadLoadedBytes(ctx, resolver.directory, reference.ID, resolver.ownerUID)
}
