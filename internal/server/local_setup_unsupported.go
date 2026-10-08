//go:build !linux

package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapters/slack"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"io"
	"os"
)

func openLocalSetupDirectory(string, uint32) (*os.File, error) {
	return nil, setupFailure(generated.ErrorCodeUnsupportedPlatform)
}
func readLocalSetupProtected(context.Context, string, uint32, int64) ([]byte, error) {
	return nil, setupFailure(generated.ErrorCodeUnsupportedPlatform)
}
func localSetupHostIdentity(context.Context) (string, error) {
	return "", setupFailure(generated.ErrorCodeUnsupportedPlatform)
}
func openLocalSetupExecutable() (io.ReadCloser, error) {
	return nil, setupFailure(generated.ErrorCodeUnsupportedPlatform)
}
func localSetupAbsent(string, uint32) error {
	return setupFailure(generated.ErrorCodeUnsupportedPlatform)
}
func writeLocalSetupReceipt(context.Context, string, uint32, []byte) error {
	return setupFailure(generated.ErrorCodeUnsupportedPlatform)
}
func newLocalSetupCredentialResolver(uint32) (slack.CredentialResolver, io.Closer, error) {
	return nil, nil, setupFailure(generated.ErrorCodeUnsupportedPlatform)
}
