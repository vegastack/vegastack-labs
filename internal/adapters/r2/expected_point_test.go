package r2

import (
	"context"
	"errors"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/backup"
)

type generationInspectorFixture struct {
	value backup.OffsiteGenerationObservation
	err   error
}

func (fixture generationInspectorFixture) InspectGeneration(context.Context, string, string) (backup.OffsiteGenerationObservation, error) {
	return fixture.value, fixture.err
}

func TestExpectedPointSourceRejectsCrossGenerationObservation(t *testing.T) {
	pending := backup.PendingOffsiteGeneration{GenerationID: "generation-a", RepositoryID: "repository-a", OffsiteSnapshotID: "snapshot-a"}
	source := ExpectedPointSource{Inspector: generationInspectorFixture{value: backup.OffsiteGenerationObservation{GenerationID: "generation-b", RepositoryID: "repository-a"}}}
	if _, err := source.ObserveExpectedPoint(context.Background(), pending); err == nil {
		t.Fatal("cross-generation observation accepted")
	}
	source.Inspector = generationInspectorFixture{err: errors.New("provider unavailable")}
	if _, err := source.ObserveExpectedPoint(context.Background(), pending); err == nil {
		t.Fatal("provider outage accepted")
	}
}
