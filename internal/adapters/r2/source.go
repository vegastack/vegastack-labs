package r2

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/vegastack/vegastack-labs/internal/backup"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type VerifiedSourceCatalog interface {
	GetVerifiedCriticalOffsiteSource(context.Context, string) (store.VerifiedCriticalOffsiteSource, error)
}

type StoreSource struct{ Catalog VerifiedSourceCatalog }

func (source StoreSource) VerifiedCriticalPoint(ctx context.Context, pointID string) (backup.VerifiedCriticalPoint, error) {
	if source.Catalog == nil {
		return backup.VerifiedCriticalPoint{}, errors.New("offsite source unavailable")
	}
	record, err := source.Catalog.GetVerifiedCriticalOffsiteSource(ctx, pointID)
	if err != nil {
		return backup.VerifiedCriticalPoint{}, err
	}
	var manifest backup.CreationManifest
	if json.Unmarshal(record.ManifestJSON, &manifest) != nil {
		return backup.VerifiedCriticalPoint{}, errors.New("offsite source manifest invalid")
	}
	_, digest, err := backup.CanonicalCreationManifest(manifest)
	if err != nil || digest != record.ManifestDigest || manifest.PointID != record.PointID || manifest.PolicyDigest != record.PolicyDigest || manifest.InventoryDigest != record.InventoryDigest {
		return backup.VerifiedCriticalPoint{}, errors.New("offsite source manifest mismatch")
	}
	return backup.VerifiedCriticalPoint{
		PointID: record.PointID, PolicyID: record.PolicyID, PolicyDigest: record.PolicyDigest, RepositoryID: record.RepositoryID, RepositoryClass: record.RepositoryClass,
		ManifestDigest: record.ManifestDigest, SnapshotID: manifest.SnapshotID, InventoryDigest: record.InventoryDigest, ContentDigest: record.ContentDigest,
		KeyReferenceID: manifest.KeyReferenceID, ResticDigest: manifest.ResticDigest, DependencyDigest: manifest.DependencyInventoryDigest,
		ProofStatus: record.ProofStatus, ProofClass: record.ProofClass, VerificationID: record.VerificationID,
		SourceRevision: record.SourceRevision, StateRevision: record.StateRevision, RecoveryEpoch: record.RecoveryEpoch,
		ObjectCount: manifest.ExpectedObjectCount, ObjectBytes: manifest.ExpectedObjectBytes,
		ExpectedObjects: append([]backup.ExpectedObject(nil), manifest.ExpectedObjects...), ExpectedDependencies: append([]backup.ExpectedDependency(nil), manifest.ExpectedDependencies...),
		FullReadValidUntil: record.FullReadValidUntil, FunctionalValidUntil: record.FunctionalValidUntil,
	}, nil
}

var _ backup.OffsiteSource = StoreSource{}
