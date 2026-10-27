package hostaction

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"io"
)

const CIJobAction = "ci.job.execute"

// CIHandler is the one finite CI-only duplex extension after signed host
// authorization. Ordinary actions retain immediate-EOF semantics.
type CIHandler interface {
	ExecuteCI(context.Context, generated.HostActionBundle, io.ReadCloser, io.Writer) (generated.HostActionResult, error)
}
type ciReadCloser struct {
	io.Reader
	io.Closer
}
