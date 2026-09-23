package localbackup

import (
	"context"

	"github.com/vegastack/vegastack-labs/internal/backup"
)

// DependencyTrustRequest is the exact point/revision/epoch-bound claim that
// independent current trust evidence must satisfy before a live proof.
type DependencyTrustRequest struct {
	PointID, PolicyDigest, ResticDigest, CatalogDigest string
	StateRevision, RecoveryEpoch                       int64
	Expected                                           []backup.ExpectedDependency
}

type DependencyTrustEvidence struct {
	DependencyID, Kind, Digest, SourceKind, PointID, PolicyDigest         string
	SourceID, ArtifactID, BundleDigest                                    string
	TrustedRootReferenceID, TrustRootDigest, SignerIdentity, SignerIssuer string
	SourceRevision, StateRevision, RecoveryEpoch                          int64
}

type DependencyTrustVerifier interface {
	VerifyCurrent(context.Context, DependencyTrustRequest) ([]DependencyTrustEvidence, error)
}
