//go:build linux

package localbackup

import (
	"context"

	"github.com/vegastack/vegastack-labs/internal/backup"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

// NewProtectedLocalDependencyTrust proves only dependencies with an existing
// protected local authority: the pinned restic executable and the inspected
// current SQLite schema catalog. Config/image/signature need a separately
// trusted current resolver and fail closed here; their manifest digests alone
// are historical provenance, not evidence.
func NewProtectedLocalDependencyTrust() DependencyTrustVerifier {
	return protectedLocalDependencyTrust{}
}

type protectedLocalDependencyTrust struct{}

func (protectedLocalDependencyTrust) VerifyCurrent(ctx context.Context, request DependencyTrustRequest) ([]DependencyTrustEvidence, error) {
	if ctx.Err() != nil || request.PointID == "" || request.PolicyDigest == "" ||
		request.StateRevision < 0 || request.RecoveryEpoch < 0 || request.ResticDigest != pinnedResticDigest() ||
		request.CatalogDigest == "" {
		return nil, backupError(generated.ErrorCodePrerequisiteBlocked, "local-backup-dependency-trust")
	}
	evidence := make([]DependencyTrustEvidence, 0, len(request.Expected))
	for _, dependency := range request.Expected {
		if !trustedLocalDependency(dependency, request) {
			return nil, backupError(generated.ErrorCodePrerequisiteBlocked, "local-backup-dependency-trust")
		}
		evidence = append(evidence, DependencyTrustEvidence{DependencyID: dependency.DependencyID, Kind: dependency.Kind,
			Digest: dependency.Digest, SourceKind: "protected-local-pin", PointID: request.PointID, PolicyDigest: request.PolicyDigest,
			SourceID: "protected-local-pin", StateRevision: request.StateRevision, RecoveryEpoch: request.RecoveryEpoch})
	}
	return evidence, nil
}

func trustedLocalDependency(dependency backup.ExpectedDependency, request DependencyTrustRequest) bool {
	switch dependency.Kind {
	case "binary":
		return dependency.Digest == request.ResticDigest
	case "schema":
		return dependency.Digest == request.CatalogDigest
	default:
		return false
	}
}

func exactDependencyTrust(expected []backup.ExpectedDependency, evidence []DependencyTrustEvidence, revision, epoch int64) bool {
	if len(expected) != len(evidence) {
		return false
	}
	seen := map[string]bool{}
	for index, dependency := range expected {
		proof := evidence[index]
		if seen[proof.DependencyID] || proof.DependencyID != dependency.DependencyID || proof.Kind != dependency.Kind ||
			proof.Digest != dependency.Digest || proof.SourceKind != "protected-local-pin" ||
			proof.StateRevision != revision || proof.RecoveryEpoch != epoch {
			return false
		}
		seen[proof.DependencyID] = true
	}
	return true
}
