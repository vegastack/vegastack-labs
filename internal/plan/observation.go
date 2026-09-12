package plan

import (
	"context"
	"sort"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/stateexport"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type RevisionReader interface {
	CurrentRevision(context.Context) (store.RevisionToken, error)
}

// StateObservationReader binds a plan to the current authoritative local
// revision and the exact declared operation facts without contacting a
// provider. Later adapters can supply richer observations through the same
// interface without changing canonical plan construction.
type StateObservationReader struct{ revisions RevisionReader }

func NewStateObservationReader(revisions RevisionReader) (*StateObservationReader, error) {
	if revisions == nil {
		return nil, planError(generated.ErrorCodeInputInvalid)
	}
	return &StateObservationReader{revisions: revisions}, nil
}

func (reader *StateObservationReader) CurrentFingerprint(ctx context.Context, declarationID string, operations []generated.DeclarationOperation) (string, error) {
	if _, err := reader.revisions.CurrentRevision(ctx); err != nil {
		return "", err
	}
	ordered := append([]generated.DeclarationOperation(nil), operations...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Sequence < ordered[j].Sequence })
	value := struct {
		DeclarationID string                           `json:"declarationId"`
		Operations    []generated.DeclarationOperation `json:"operations"`
	}{declarationID, ordered}
	_, sum, err := stateexport.CanonicalJSON(value)
	if err != nil {
		return "", planError(generated.ErrorCodeInputInvalid)
	}
	return digest(sum), nil
}
