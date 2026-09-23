package backup

import (
	"bytes"
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
	rules := make([]store.OffsiteRuleRecord, len(pending.ProtectedRules))
	for index, rule := range pending.ProtectedRules {
		rules[index] = store.OffsiteRuleRecord{RuleID: rule.RuleID, Prefix: rule.Prefix}
	}
	objects := make([]store.OffsiteObjectRecord, len(pending.Objects))
	for index, object := range pending.Objects {
		objects[index] = store.OffsiteObjectRecord{Key: object.Key, Digest: object.Digest, Bytes: object.Bytes}
	}
	return catalog.repository.AppendGeneration(ctx, store.OffsiteGenerationRecord{GenerationID: pending.GenerationID, SourcePointID: pending.SourcePointID,
		RepositoryID: pending.RepositoryID, SnapshotID: pending.OffsiteSnapshotID, CanonicalJSON: body, SessionExpiries: append([]time.Time(nil), pending.SessionExpiries...),
		Rules: rules, Objects: objects, SourceRevision: pending.SourceRevision, StateRevision: pending.StateRevision, RecoveryEpoch: pending.RecoveryEpoch, IssuanceStoppedAt: pending.IssuanceStoppedAt})
}

func (catalog *SQLCatalog) GetGeneration(ctx context.Context, generationID string) (PendingOffsiteGeneration, error) {
	return catalog.pending(ctx, generationID)
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
	return catalog.repository.AppendLastGood(ctx, proof.ProofID, proof.ProofDigest, proof.GenerationID, proof.SourceRevision, proof.StateRevision, proof.RecoveryEpoch)
}

func (catalog *SQLCatalog) ProofExists(ctx context.Context, generationID, proofDigest string) (bool, error) {
	return catalog.repository.ProofExists(ctx, generationID, proofDigest)
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
	record, err := catalog.repository.Generation(ctx, generationID)
	if err != nil {
		return PendingOffsiteGeneration{}, err
	}
	var pending PendingOffsiteGeneration
	if json.Unmarshal(record.CanonicalJSON, &pending) != nil || pending.GenerationID != generationID || ValidatePendingOffsiteGeneration(pending) != nil {
		return PendingOffsiteGeneration{}, errors.New("stored offsite generation failed validation")
	}
	canonical, err := json.Marshal(pending)
	if err != nil || !bytes.Equal(canonical, record.CanonicalJSON) || pending.SourcePointID != record.SourcePointID || pending.RepositoryID != record.RepositoryID ||
		pending.OffsiteSnapshotID != record.SnapshotID || pending.SourceRevision != record.SourceRevision || pending.StateRevision != record.StateRevision ||
		pending.RecoveryEpoch != record.RecoveryEpoch || !pending.IssuanceStoppedAt.Equal(record.IssuanceStoppedAt) || len(pending.SessionExpiries) != len(record.SessionExpiries) ||
		len(pending.ProtectedRules) != len(record.Rules) || len(pending.Objects) != len(record.Objects) {
		return PendingOffsiteGeneration{}, errors.New("stored offsite generation projection mismatch")
	}
	for index, expiry := range pending.SessionExpiries {
		if !expiry.Equal(record.SessionExpiries[index]) {
			return PendingOffsiteGeneration{}, errors.New("stored offsite session projection mismatch")
		}
	}
	for index, rule := range pending.ProtectedRules {
		if rule.RuleID != record.Rules[index].RuleID || rule.Prefix != record.Rules[index].Prefix {
			return PendingOffsiteGeneration{}, errors.New("stored offsite rule projection mismatch")
		}
	}
	for index, object := range pending.Objects {
		if object.Key != record.Objects[index].Key || object.Digest != record.Objects[index].Digest || object.Bytes != record.Objects[index].Bytes {
			return PendingOffsiteGeneration{}, errors.New("stored offsite object projection mismatch")
		}
	}
	return pending, nil
}

var _ OffsiteCatalog = (*SQLCatalog)(nil)
