package r2

import (
	"context"
	"errors"

	"github.com/vegastack/vegastack-labs/internal/backup"
)

// GenerationInspector is the narrow R2 read adapter used after a copy. Its
// implementation must list the named generation and run the configured full
// read; it receives no writer or retention-admin authority.
type GenerationInspector interface {
	InspectGeneration(context.Context, string, string) (backup.OffsiteGenerationObservation, error)
}

type ExpectedPointSource struct{ Inspector GenerationInspector }

func (source ExpectedPointSource) ObserveExpectedPoint(ctx context.Context, pending backup.PendingOffsiteGeneration) (backup.OffsiteGenerationObservation, error) {
	if source.Inspector == nil || pending.GenerationID == "" || pending.RepositoryID == "" || pending.OffsiteSnapshotID == "" {
		return backup.OffsiteGenerationObservation{}, errors.New("r2 expected point inspection blocked")
	}
	observed, err := source.Inspector.InspectGeneration(ctx, pending.GenerationID, pending.RepositoryID)
	if err != nil {
		return backup.OffsiteGenerationObservation{}, err
	}
	if observed.GenerationID != pending.GenerationID || observed.RepositoryID != pending.RepositoryID {
		return backup.OffsiteGenerationObservation{}, errors.New("r2 generation identity mismatch")
	}
	return observed, nil
}
