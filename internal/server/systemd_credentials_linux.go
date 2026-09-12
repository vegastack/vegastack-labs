//go:build linux

package server

import (
	"context"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

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
	if resolver == nil || resolver.directory == nil || ctx == nil || reference.Consumer != "slack-acknowledgement" || reference.ID == "" || filepath.Base(reference.ID) != reference.ID {
		return nil, failure.New(generated.ErrorCodeAuthorizationDenied, "native-credential-reference", false)
	}
	if err := ctx.Err(); err != nil {
		return nil, failure.New(generated.ErrorCodeInterrupted, "native-credential-resolver", false)
	}
	fd, err := unix.Openat(int(resolver.directory.Fd()), reference.ID, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, failure.New(generated.ErrorCodeDependencyUnavailable, "native-credential-resolver", true)
	}
	file := os.NewFile(uintptr(fd), "credential")
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != resolver.ownerUID || stat.Mode&0o077 != 0 || stat.Size < 8 || stat.Size > 4096 {
		return nil, failure.New(generated.ErrorCodeAuthorizationDenied, "native-credential-material", false)
	}
	value, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(value) < 8 || len(value) > 4096 {
		zeroCredential(value)
		return nil, failure.New(generated.ErrorCodeDependencyUnavailable, "native-credential-resolver", true)
	}
	return value, nil
}
