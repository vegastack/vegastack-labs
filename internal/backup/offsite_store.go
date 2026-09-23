package backup

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/vegastack/vegastack-labs/internal/store"
)

// SQLCatalog keeps backup-domain validation above the provider-neutral SQLite
// record layer, avoiding a reverse dependency from store into backup.
type SQLCatalog struct{ repository *store.OffsiteRepository }

func NewSQLCatalog(authority *store.Store) *SQLCatalog {
	return &SQLCatalog{repository: store.NewOffsiteRepository(authority)}
}

func (catalog *SQLCatalog) AppendPending(ctx context.Context, pending PendingOffsiteGeneration) error {
	if catalog == nil || catalog.repository == nil || ValidatePendingOffsiteGeneration(pending) != nil {
		return errors.New("invalid pending offsite generation")
	}
	body, err := json.Marshal(pending)
	if err != nil {
		return err
	}
	return catalog.repository.AppendGeneration(ctx, store.OffsiteGenerationRecord{GenerationID: pending.GenerationID, SourcePointID: pending.SourcePointID,
		RepositoryID: pending.RepositoryID, SnapshotID: pending.OffsiteSnapshotID, CanonicalJSON: body, SessionExpiries: append([]time.Time(nil), pending.SessionExpiries...),
		SourceRevision: pending.SourceRevision, RecoveryEpoch: pending.RecoveryEpoch, IssuanceStoppedAt: pending.IssuanceStoppedAt})
}

func (catalog *SQLCatalog) AppendProof(ctx context.Context, proof OffsiteProof) error {
	pending, err := catalog.pending(ctx, proof.GenerationID)
	if err != nil {
		return err
	}
	if err := ValidateOffsiteProof(pending, proof); err != nil {
		return err
	}
	body, err := json.Marshal(proof)
	if err != nil {
		return err
	}
	return catalog.repository.AppendProof(ctx, store.OffsiteProofRecord{ProofID: proof.ProofID, ProofDigest: proof.ProofDigest, GenerationID: proof.GenerationID,
		Status: proof.Status, ProofClass: proof.ProofClass, CanonicalJSON: body, FullReadAt: proof.FullReadAt, ObservedAt: proof.ObservedAt, RecoveryEpoch: proof.RecoveryEpoch})
}

func (catalog *SQLCatalog) AdvanceLastGood(ctx context.Context, proof OffsiteProof, currentRevision int64) error {
	pending, err := catalog.pending(ctx, proof.GenerationID)
	if err != nil {
		return err
	}
	if err := CanAdvanceOffsiteLastGood(pending, proof, currentRevision, proof.RecoveryEpoch); err != nil {
		return err
	}
	return catalog.repository.AppendLastGood(ctx, proof.ProofID, proof.ProofDigest, proof.GenerationID, proof.SourceRevision, currentRevision, proof.RecoveryEpoch)
}

func (catalog *SQLCatalog) Status(ctx context.Context, generationID string) (OffsiteStatus, error) {
	value, err := catalog.repository.Status(ctx, generationID)
	if err != nil {
		return OffsiteStatus{}, err
	}
	return OffsiteStatus{GenerationID: value.GenerationID, Status: value.Status, ProofClass: value.ProofClass, LastGoodProofID: value.LastGoodProofID,
		SourcePointID: value.SourcePointID, RepositoryID: value.RepositoryID, SnapshotID: value.SnapshotID, RecoveryEpoch: value.RecoveryEpoch}, nil
}

func (catalog *SQLCatalog) pending(ctx context.Context, generationID string) (PendingOffsiteGeneration, error) {
	body, err := catalog.repository.GenerationJSON(ctx, generationID)
	if err != nil {
		return PendingOffsiteGeneration{}, err
	}
	var pending PendingOffsiteGeneration
	if json.Unmarshal(body, &pending) != nil || pending.GenerationID != generationID || ValidatePendingOffsiteGeneration(pending) != nil {
		return PendingOffsiteGeneration{}, errors.New("stored offsite generation failed validation")
	}
	return pending, nil
}

var _ OffsiteCatalog = (*SQLCatalog)(nil)
