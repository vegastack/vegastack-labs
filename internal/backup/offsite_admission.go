package backup

import (
	"context"
	"errors"
	"time"
)

func AdmitOffsitePoint(ctx context.Context, source OffsiteSource, policy OffsitePolicy, pointID string, expectedEpoch int64) (VerifiedCriticalPoint, error) {
	invalid := errors.New("offsite source is not a current verified critical point")
	if source == nil || pointID == "" || expectedEpoch < 0 || !validOffsitePolicy(policy) {
		return VerifiedCriticalPoint{}, invalid
	}
	point, err := source.VerifiedCriticalPoint(ctx, pointID)
	if err != nil {
		return VerifiedCriticalPoint{}, err
	}
	now := time.Now().UTC()
	if policy.Clock != nil {
		now = policy.Clock().UTC()
	}
	if point.PointID != pointID || point.PolicyID != policy.PolicyID || point.RepositoryClass != "critical" ||
		point.ProofStatus != OffsiteProofLocalVerified || point.ProofClass != OffsiteProofClassLive ||
		point.RecoveryEpoch != expectedEpoch || point.StateRevision < 0 || point.SourceRevision < 0 ||
		point.VerificationID == "" || point.RepositoryID == "" || point.SnapshotID == "" || point.KeyReferenceID == "" ||
		!validBackupManifestDigest(point.ManifestDigest) || !validBackupManifestDigest(point.PolicyDigest) ||
		!validBackupManifestDigest(point.InventoryDigest) || !validBackupManifestDigest(point.ContentDigest) ||
		!validBackupManifestDigest(point.ResticDigest) || !validBackupManifestDigest(point.DependencyDigest) ||
		point.ObjectCount != int64(len(point.ExpectedObjects)) || point.ObjectCount < 1 || point.ObjectBytes < 1 ||
		ExpectedInventoryDigest(point.ExpectedObjects) != point.InventoryDigest ||
		ExpectedDependencyInventoryDigest(point.ExpectedDependencies) != point.DependencyDigest ||
		!now.Before(point.FullReadValidUntil) || !now.Before(point.FunctionalValidUntil) {
		return VerifiedCriticalPoint{}, invalid
	}
	var bytes int64
	snapshots := 0
	for _, object := range point.ExpectedObjects {
		bytes += object.Bytes
		if object.Type == "snapshots" && object.Name == point.SnapshotID {
			snapshots++
		}
	}
	if bytes != point.ObjectBytes || snapshots != 1 {
		return VerifiedCriticalPoint{}, invalid
	}
	return point, nil
}

func validOffsitePolicy(policy OffsitePolicy) bool {
	return policy.PolicyID != "" && policy.ProfileID != "" && validOffsiteToken(policy.GenerationID) &&
		policy.Bucket != "" && validOffsitePrefix(policy.Prefix) && policy.ParentReferenceID != "" &&
		validBackupManifestDigest(policy.ParentFingerprint) && policy.MaximumBytes > 0 && policy.MaximumPUTs > 0 &&
		policy.MaximumLISTs > 0 && policy.MaximumRetainedGenerations > 0 && policy.RuleLimit > 0 &&
		policy.RetentionWindow > 0 && policy.SessionTTL > 0 && policy.SessionTTL <= 15*time.Minute
}
