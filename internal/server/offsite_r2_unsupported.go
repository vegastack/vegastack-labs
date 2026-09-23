//go:build !linux

package server

import (
	"context"
	"errors"

	"github.com/vegastack/vegastack-labs/internal/generated"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func NewLabsR2Runner(context.Context, serverconfig.Profile, *store.Store, generated.GateEvidence) (runengine.OffsiteCopyRunner, error) {
	return nil, errors.New("r2 runtime requires linux custody")
}
