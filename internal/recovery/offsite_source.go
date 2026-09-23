package recovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/vegastack/vegastack-labs/internal/backup"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// SQLOffsiteSourceReader composes #114's append-only generation/proof catalog
// with the exact critical local point. It returns no repository credential.
type SQLOffsiteSourceReader struct {
	Local   *store.BackupRepository
	Offsite *store.OffsiteRepository
}

func (reader SQLOffsiteSourceReader) CurrentOffsiteRecoverySource(ctx context.Context, pointID string) (OffsiteRecoverySource, error) {
	blocked := func(target string) (OffsiteRecoverySource, error) {
		return OffsiteRecoverySource{}, failure.New(generated.ErrorCodePrerequisiteBlocked, target, false)
	}
	if reader.Local == nil || reader.Offsite == nil || pointID == "" {
		return blocked("restore-offsite-source")
	}
	local, err := reader.Local.GetVerifiedCriticalOffsiteSource(ctx, pointID)
	if err != nil {
		return OffsiteRecoverySource{}, err
	}
	lastGood, err := reader.Offsite.CurrentLastGoodForPoint(ctx, pointID)
	if err != nil {
		return OffsiteRecoverySource{}, err
	}
	var generation backup.PendingOffsiteGeneration
	var proof backup.OffsiteProof
	var manifest backup.CreationManifest
	if json.Unmarshal(lastGood.GenerationJSON, &generation) != nil || json.Unmarshal(lastGood.ProofJSON, &proof) != nil || json.Unmarshal(local.ManifestJSON, &manifest) != nil ||
		backup.ValidatePendingOffsiteGeneration(generation) != nil || backup.ValidateOffsiteProof(generation, proof) != nil {
		return blocked("restore-offsite-source-record")
	}
	canonicalGeneration, generationErr := json.Marshal(generation)
	canonicalProof, proofErr := json.Marshal(proof)
	manifestSum := sha256.Sum256(local.ManifestJSON)
	manifestDigest := "sha256:" + hex.EncodeToString(manifestSum[:])
	if generationErr != nil || proofErr != nil || !bytes.Equal(canonicalGeneration, lastGood.GenerationJSON) || !bytes.Equal(canonicalProof, lastGood.ProofJSON) ||
		manifestDigest != local.ManifestDigest || lastGood.PointID != pointID || lastGood.GenerationID != generation.GenerationID || lastGood.ProofID != proof.ProofID ||
		lastGood.ProofDigest != proof.ProofDigest || lastGood.Status != backup.OffsiteStatusVerified || lastGood.ProofClass != backup.OffsiteProofQualified ||
		proof.Status != backup.OffsiteStatusVerified || proof.ProofClass != backup.OffsiteProofQualified || generation.SourcePointID != pointID || proof.SourcePointID != pointID ||
		proof.GenerationID != generation.GenerationID || proof.OffsiteSnapshotID != generation.OffsiteSnapshotID || proof.OffsiteInventoryDigest != generation.OffsiteInventoryDigest ||
		proof.SourceManifestDigest != local.ManifestDigest || proof.SourceContentDigest != local.ContentDigest || proof.SourceInventoryDigest != local.InventoryDigest ||
		manifest.PointID != pointID || manifest.ContentDigest != local.ContentDigest ||
		manifest.InventoryDigest != local.InventoryDigest || manifest.DatabaseSchemaVersion == 0 || manifest.RecoveryEpoch != lastGood.RecoveryEpoch ||
		lastGood.SourceRevision != generation.SourceRevision || lastGood.StateRevision != generation.StateRevision || lastGood.RecoveryEpoch != generation.RecoveryEpoch ||
		lastGood.FullReadAt.IsZero() || !lastGood.FullReadAt.Equal(proof.FullReadAt) || !lastGood.ObservedAt.Equal(proof.ObservedAt) {
		return blocked("restore-offsite-source-binding")
	}
	dependencies := make([]string, len(manifest.ExpectedDependencies))
	for index, dependency := range manifest.ExpectedDependencies {
		dependencies[index] = dependency.Digest
	}
	return OffsiteRecoverySource{PointID: pointID, GenerationID: generation.GenerationID, RepositoryID: generation.RepositoryID, SnapshotID: generation.OffsiteSnapshotID,
		ManifestDigest: local.ManifestDigest, InventoryDigest: generation.OffsiteInventoryDigest, ContentDigest: local.ContentDigest, VerificationDigest: proof.ProofDigest,
		CatalogDigest: manifest.CatalogDigest, DependencyDigest: manifest.DependencyInventoryDigest, KeyReferenceID: generation.KeyReferenceID,
		Status: proof.Status, ProofClass: proof.ProofClass, SourceRevision: generation.SourceRevision, StateRevision: lastGood.StateRevision, RecoveryEpoch: generation.RecoveryEpoch,
		CurrentStateRevision: lastGood.CurrentStateRevision, CurrentRecoveryEpoch: lastGood.CurrentRecoveryEpoch, DatabaseSchemaVersion: int64(manifest.DatabaseSchemaVersion),
		CreatedAt: local.CreatedAt, VerifiedAt: proof.ObservedAt, FullReadValidUntil: local.FullReadValidUntil, FunctionalValidUntil: local.FunctionalValidUntil,
		DependencyDigests: dependencies}, nil
}
