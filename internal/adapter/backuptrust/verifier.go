package backuptrust

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/adapter/localbackup"
	"github.com/vegastack/vegastack-labs/internal/backup"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/release"
	"github.com/vegastack/vegastack-labs/internal/store"
)

const (
	maxArtifactBytes = 16 << 20
	maxBundleBytes   = 4 << 20
	maxRootBytes     = 4 << 20
)

type SourceCatalog interface {
	GetCurrentBackupTrustSourceForDependency(context.Context, string, string, int64, int64) (store.BackupTrustSourceDraft, error)
}

// Verifier composes the already-proven protected binary/schema pins with
// signed registered sources for config/image/signature dependencies.
type Verifier struct {
	sources SourceCatalog
	reader  ArtifactReader
	local   localbackup.DependencyTrustVerifier
}

func NewVerifier(sources SourceCatalog, reader ArtifactReader, local localbackup.DependencyTrustVerifier) *Verifier {
	return &Verifier{sources: sources, reader: reader, local: local}
}

func (verifier *Verifier) VerifyCurrent(ctx context.Context, request localbackup.DependencyTrustRequest) ([]localbackup.DependencyTrustEvidence, error) {
	if verifier == nil || verifier.sources == nil || verifier.reader == nil || ctx.Err() != nil || request.PointID == "" ||
		!validDigest(request.PolicyDigest) || request.StateRevision < 0 || request.RecoveryEpoch < 0 || len(request.Expected) == 0 {
		return nil, trustError()
	}
	evidence := make([]localbackup.DependencyTrustEvidence, 0, len(request.Expected))
	seen := make(map[string]struct{}, len(request.Expected))
	for _, dependency := range request.Expected {
		if _, duplicate := seen[dependency.DependencyID]; duplicate || dependency.DependencyID == "" || !validDigest(dependency.Digest) {
			return nil, trustError()
		}
		seen[dependency.DependencyID] = struct{}{}
		switch dependency.Kind {
		case "binary", "schema":
			if verifier.local == nil {
				return nil, trustError()
			}
			localRequest := request
			localRequest.Expected = []backup.ExpectedDependency{dependency}
			rows, err := verifier.local.VerifyCurrent(ctx, localRequest)
			if err != nil || len(rows) != 1 {
				return nil, trustError()
			}
			evidence = append(evidence, rows[0])
		case "config", "image", "signature":
			row, err := verifier.verifySigned(ctx, request, dependency)
			if err != nil {
				return nil, err
			}
			evidence = append(evidence, row)
		default:
			return nil, trustError()
		}
	}
	return evidence, nil
}

func (verifier *Verifier) verifySigned(ctx context.Context, request localbackup.DependencyTrustRequest, dependency backup.ExpectedDependency) (localbackup.DependencyTrustEvidence, error) {
	source, err := verifier.sources.GetCurrentBackupTrustSourceForDependency(ctx, dependency.DependencyID, dependency.Kind, request.StateRevision, request.RecoveryEpoch)
	if err != nil || source.DependencyID != dependency.DependencyID || source.DependencyKind != dependency.Kind ||
		source.ArtifactDigest != dependency.Digest || source.RecoveryEpoch != request.RecoveryEpoch || source.StateRevision > request.StateRevision ||
		!validDigest(source.ArtifactDigest) || !validDigest(source.BundleDigest) || !validDigest(source.TrustRootDigest) ||
		source.SourceID == "" || source.ArtifactID == "" || source.TrustedRootReferenceID == "" || source.SignerIdentity == "" || source.SignerIssuer == "" {
		return localbackup.DependencyTrustEvidence{}, trustError()
	}
	artifact, bundleJSON, trustedRoot, observedDigest, err := verifier.reader.OpenRegistered(ctx, source.SourceID, source.ArtifactID, request.RecoveryEpoch)
	if err != nil || artifact == nil {
		return localbackup.DependencyTrustEvidence{}, trustError()
	}
	content, readErr := io.ReadAll(io.LimitReader(artifact, maxArtifactBytes+1))
	closeErr := artifact.Close()
	if readErr != nil || closeErr != nil || len(content) == 0 || len(content) > maxArtifactBytes || len(bundleJSON) == 0 || len(bundleJSON) > maxBundleBytes || len(trustedRoot) == 0 || len(trustedRoot) > maxRootBytes {
		return localbackup.DependencyTrustEvidence{}, trustError()
	}
	artifactDigest := digest(content)
	if artifactDigest != observedDigest || artifactDigest != source.ArtifactDigest || digest(bundleJSON) != source.BundleDigest || digest(trustedRoot) != source.TrustRootDigest {
		return localbackup.DependencyTrustEvidence{}, trustError()
	}
	policy := generated.ReleaseTrustPolicy{Schema: generated.SchemaIDReleaseTrustPolicy, SchemaVersion: "1.0.0",
		CertificateIdentity: source.SignerIdentity, OIDCIssuer: source.SignerIssuer, TrustedRoot: append([]byte(nil), trustedRoot...)}
	if err := (release.SigstoreBundleVerifier{}).Verify(ctx, bytes.NewReader(content), bundleJSON, policy); err != nil {
		return localbackup.DependencyTrustEvidence{}, trustError()
	}
	return localbackup.DependencyTrustEvidence{
		DependencyID: dependency.DependencyID, Kind: dependency.Kind, Digest: dependency.Digest,
		SourceKind: "registered-signed-artifact", PointID: request.PointID, PolicyDigest: request.PolicyDigest,
		SourceID: source.SourceID, ArtifactID: source.ArtifactID, BundleDigest: source.BundleDigest,
		TrustedRootReferenceID: source.TrustedRootReferenceID, TrustRootDigest: source.TrustRootDigest,
		SignerIdentity: source.SignerIdentity, SourceRevision: source.Revision,
		StateRevision: request.StateRevision, RecoveryEpoch: request.RecoveryEpoch,
	}, nil
}

func digest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func trustError() error {
	return failure.New(generated.ErrorCodePrerequisiteBlocked, "backup-dependency-trust", false)
}
