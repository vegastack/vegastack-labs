//go:build !linux

package backup

import (
	"context"
	"net"
	"time"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

// RESTServer is unavailable off Linux: the guarded object boundary depends on
// openat2, O_NOFOLLOW and SO_PEERCRED. It fails closed.
type RESTServer struct{}

func NewRESTServer(_ string, _ uint32, _ WriterLease, _ LeaseVerifier, _ func() time.Time) (*RESTServer, error) {
	return nil, failure.New(generated.ErrorCodeUnsupportedPlatform, "backup-rest", false)
}

func (*RESTServer) Serve(context.Context, net.Listener) error {
	return failure.New(generated.ErrorCodeUnsupportedPlatform, "backup-rest", false)
}
