//go:build !linux

package runnerbootstrap

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

func Configure(context.Context, Config, *credentialref.Value) (Receipt, error) {
	return Receipt{}, failure.New(generated.ErrorCodeUnsupportedPlatform, "runner-bootstrap", false)
}
