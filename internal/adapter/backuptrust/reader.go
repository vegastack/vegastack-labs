package backuptrust

import (
	"context"
	"io"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

// ArtifactReader exposes only administrator-registered logical source and
// artifact IDs. It deliberately has no path or provider-CLI parameter.
type ArtifactReader interface {
	OpenRegistered(context.Context, string, string, int64) (artifact io.ReadCloser, bundleJSON, trustedRoot []byte, observedDigest string, err error)
}

// UnavailableArtifactReader is the production default until a site registers
// and separately qualifies a concrete protected artifact/root source.
type UnavailableArtifactReader struct{}

func (UnavailableArtifactReader) OpenRegistered(context.Context, string, string, int64) (io.ReadCloser, []byte, []byte, string, error) {
	return nil, nil, nil, "", failure.New(generated.ErrorCodePrerequisiteBlocked, "backup-trust-artifact-source", false)
}
