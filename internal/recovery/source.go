package recovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

var restoreDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type SourceSelection struct {
	PointID              string
	SourceClass          string
	RepositoryClass      string
	DeclaredRPOSeconds   int64
	TargetReleaseBuildID string
	TargetToolVersion    string
	TargetSchemaVersion  string
}

// CandidateTarget is implemented only inside this package by the isolated
// candidate manager. A caller cannot turn a qualified source into an arbitrary
// path restore.
type CandidateTarget interface{ recoveryCandidateTarget() }

type SnapshotReceipt struct {
	PointID, SnapshotID, ContentDigest string
	Bytes                              int64
}

type SnapshotReader interface {
	Restore(context.Context, CandidateTarget) (SnapshotReceipt, error)
}

type LocalSourceReader interface {
	CurrentLocalRecoverySource(context.Context, string) (store.LocalRecoverySource, error)
}

type SnapshotResolver interface {
	ResolveLocal(context.Context, store.LocalRecoverySource) (SnapshotReader, error)
}

type CompatibilityVerifier interface {
	VerifyRestoreCompatibility(context.Context, SourceSelection, store.LocalRecoverySource) error
}

type AuditPositionVerifier interface {
	VerifyRestoreAuditPosition(context.Context, store.LocalRecoverySource, SnapshotReader) (AuditContinuity, error)
}

type VerifiedSource struct {
	Binding        generated.RestoreSourceBinding
	Snapshot       SnapshotReader
	DatabaseDigest string
	Audit          AuditContinuity
}

type SourceVerifier struct {
	Local         LocalSourceReader
	Snapshots     SnapshotResolver
	Compatibility CompatibilityVerifier
	Audit         AuditPositionVerifier
	Clock         func() time.Time
}

func (verifier SourceVerifier) Verify(ctx context.Context, selection SourceSelection) (VerifiedSource, error) {
	blocked := func(target string) (VerifiedSource, error) {
		return VerifiedSource{}, failure.New(generated.ErrorCodePrerequisiteBlocked, target, false)
	}
	if ctx == nil || ctx.Err() != nil || verifier.Local == nil || verifier.Snapshots == nil || verifier.Compatibility == nil || verifier.Audit == nil || verifier.Clock == nil ||
		selection.PointID == "" || selection.SourceClass != "local" || (selection.RepositoryClass != "standard" && selection.RepositoryClass != "critical") ||
		selection.DeclaredRPOSeconds <= 0 || selection.TargetReleaseBuildID == "" || selection.TargetToolVersion == "" || selection.TargetSchemaVersion == "" {
		return blocked("restore-source")
	}
	record, err := verifier.Local.CurrentLocalRecoverySource(ctx, selection.RepositoryClass)
	if err != nil {
		return VerifiedSource{}, err
	}
	now := verifier.Clock().UTC()
	if now.IsZero() || record.Point.PointID != selection.PointID || record.Verification.PointID != selection.PointID ||
		record.Verification.Status != "local-verified" || record.Verification.ProofClass != "live" || record.CreatedAt.After(now) || record.VerifiedAt.After(now) ||
		now.Sub(record.CreatedAt) > time.Duration(selection.DeclaredRPOSeconds)*time.Second || record.VerifiedAt.Before(record.CreatedAt) ||
		record.Point.RecoveryEpoch != record.Verification.RecoveryEpoch || strconv.FormatUint(record.DatabaseSchemaVersion, 10) != selection.TargetSchemaVersion {
		return blocked("restore-source")
	}
	for _, value := range []string{record.Point.ContentDigest, record.Point.ManifestDigest, record.Verification.ProofDigest, record.Point.InventoryDigest, record.CatalogDigest, record.DependencyDigest} {
		if !restoreDigest.MatchString(value) {
			return blocked("restore-source")
		}
	}
	if err := verifier.Compatibility.VerifyRestoreCompatibility(ctx, selection, record); err != nil {
		return VerifiedSource{}, err
	}
	reader, err := verifier.Snapshots.ResolveLocal(ctx, record)
	if err != nil || reader == nil {
		return blocked("restore-source-snapshot")
	}
	auditPosition, err := verifier.Audit.VerifyRestoreAuditPosition(ctx, record, reader)
	if err != nil || auditPosition.LocalLastEventID < 0 || auditPosition.IndependentLastEventID < auditPosition.LocalLastEventID || !restoreDigest.MatchString(auditPosition.IndependentCheckpointDigest) {
		return blocked("restore-source-audit")
	}
	dependencyDigests := make([]string, 0, len(record.Verification.DependencyTrust))
	for _, proof := range record.Verification.DependencyTrust {
		if !restoreDigest.MatchString(proof.Digest) {
			return blocked("restore-source-dependencies")
		}
		dependencyDigests = append(dependencyDigests, proof.Digest)
	}
	sort.Strings(dependencyDigests)
	pointDigest, err := localPointDigest(record)
	if err != nil {
		return blocked("restore-source")
	}
	binding := generated.RestoreSourceBinding{
		Schema: generated.SchemaIDRestoreSourceBinding, SchemaVersion: "1.1.0", PointID: record.Point.PointID,
		PointDigest: pointDigest, ManifestDigest: record.Point.ManifestDigest, VerificationDigest: record.Verification.ProofDigest,
		SourceClass: "local", RepositoryGenerationID: record.Point.RepositoryID, DeclaredRPOSeconds: selection.DeclaredRPOSeconds,
		CreatedAt: record.CreatedAt.UTC().Format(time.RFC3339), VerifiedAt: record.VerifiedAt.UTC().Format(time.RFC3339),
		RecoveryEpoch: record.Point.RecoveryEpoch, DependencyDigests: dependencyDigests,
	}
	raw, err := json.Marshal(binding)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDRestoreSourceBinding, raw, generated.ContractExact) != nil {
		return blocked("restore-source-binding")
	}
	return VerifiedSource{Binding: binding, Snapshot: reader, DatabaseDigest: record.Point.ContentDigest, Audit: auditPosition}, nil
}

func localPointDigest(record store.LocalRecoverySource) (string, error) {
	value := struct {
		Domain, PointID, SnapshotID, RepositoryID, ManifestDigest, InventoryDigest, ContentDigest, VerificationDigest string
		SourceRevision, StateRevision, RecoveryEpoch                                                                  int64
	}{"vegastack-labs.dev/restore-local-point/v1", record.Point.PointID, record.SnapshotID, record.Point.RepositoryID, record.Point.ManifestDigest, record.Point.InventoryDigest, record.Point.ContentDigest, record.Verification.ProofDigest, record.Point.SourceRevision, record.Verification.StateRevision, record.Verification.RecoveryEpoch}
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
