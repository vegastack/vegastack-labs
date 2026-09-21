//go:build !linux

package backup

import (
	"context"
	"time"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

// resticRunner is unavailable off Linux: the sealed anonymous memory password FD
// depends on memfd_create and file seals. It fails closed.
type resticRunner struct{}

func NewResticRunner() ResticRunner { return &resticRunner{} }

func NewResticRunnerForTest(string, func() time.Time) ResticRunner { return &resticRunner{} }

func (*resticRunner) Run(context.Context, ResticRequest, *credentialref.Value) (ResticResult, error) {
	return ResticResult{}, failure.New(generated.ErrorCodeUnsupportedPlatform, "backup-restic", false)
}

func (*resticRunner) Observation() ResticObservation {
	return ResticObservation{PasswordFileMode: "unsupported"}
}
