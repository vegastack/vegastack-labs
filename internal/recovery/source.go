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
	InspectAudit(context.Context) (AuditContinuity, error)
	Restore(context.Context, CandidateTarget, generated.RestoreBinding) (SnapshotReceipt, error)
}

type LocalSourceReader interface {
	CurrentLocalRecoverySource(context.Context, string) (store.LocalRecoverySource, error)
}

type SnapshotResolver interface {
	ResolveLocal(context.Context, store.LocalRecoverySource) (SnapshotReader, error)
}

// OffsiteRecoverySource is the secret-free, exact generation selected by the
// durable off-site last-good record. Repository credentials remain behind the
// resolver boundary.
type OffsiteRecoverySource struct {
	PointID, GenerationID, RepositoryID, SnapshotID                    string
	ManifestDigest, InventoryDigest, ContentDigest, VerificationDigest string
	CatalogDigest, DependencyDigest, KeyReferenceID                    string
	Status, ProofClass                                                 string
	SourceRevision, StateRevision, RecoveryEpoch, CurrentStateRevision int64
	CurrentRecoveryEpoch, DatabaseSchemaVersion                        int64
	CreatedAt, VerifiedAt, FullReadValidUntil, FunctionalValidUntil    time.Time
	DependencyDigests                                                  []string
	RequiredDependencies                                               []generated.RestoreDependencyBinding
}

type OffsiteSourceReader interface {
	CurrentOffsiteRecoverySource(context.Context, string) (OffsiteRecoverySource, error)
}

type OffsiteSnapshotResolver interface {
	ResolveOffsite(context.Context, OffsiteRecoverySource) (SnapshotReader, error)
}

type OffsiteCompatibilityVerifier interface {
	VerifyOffsiteRestoreCompatibility(context.Context, SourceSelection, OffsiteRecoverySource) error
}

type OffsiteAuditPositionVerifier interface {
	VerifyOffsiteRestoreAuditPosition(context.Context, OffsiteRecoverySource, SnapshotReader) (AuditContinuity, error)
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
	Local                LocalSourceReader
	Snapshots            SnapshotResolver
	Compatibility        CompatibilityVerifier
	Audit                AuditPositionVerifier
	Offsite              OffsiteSourceReader
	OffsiteSnapshots     OffsiteSnapshotResolver
	OffsiteCompatibility OffsiteCompatibilityVerifier
	OffsiteAudit         OffsiteAuditPositionVerifier
	Clock                func() time.Time
}

func (verifier SourceVerifier) Verify(ctx context.Context, selection SourceSelection) (VerifiedSource, error) {
	blocked := func(target string) (VerifiedSource, error) {
		return VerifiedSource{}, failure.New(generated.ErrorCodePrerequisiteBlocked, target, false)
	}
	if ctx == nil || ctx.Err() != nil || verifier.Clock == nil || selection.PointID == "" ||
		(selection.SourceClass != "local" && selection.SourceClass != "off-site") || (selection.RepositoryClass != "standard" && selection.RepositoryClass != "critical") ||
		selection.DeclaredRPOSeconds <= 0 || selection.TargetReleaseBuildID == "" || selection.TargetToolVersion == "" || selection.TargetSchemaVersion == "" {
		return blocked("restore-source")
	}
	if selection.SourceClass == "off-site" {
		return verifier.verifyOffsite(ctx, selection)
	}
	if verifier.Local == nil || verifier.Snapshots == nil || verifier.Compatibility == nil || verifier.Audit == nil {
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
		record.Point.RecoveryEpoch != record.Verification.RecoveryEpoch || !validWitnessToken(record.KeyReferenceID) || strconv.FormatUint(record.DatabaseSchemaVersion, 10) != selection.TargetSchemaVersion {
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
	requiredDependencies := make([]generated.RestoreDependencyBinding, 0, len(record.Verification.DependencyTrust))
	for _, proof := range record.Verification.DependencyTrust {
		if !validWitnessToken(proof.DependencyID) || !restoreDigest.MatchString(proof.Digest) {
			return blocked("restore-source-dependencies")
		}
		dependencyDigests = append(dependencyDigests, proof.Digest)
		requiredDependencies = append(requiredDependencies, generated.RestoreDependencyBinding{DependencyID: proof.DependencyID, Kind: proof.Kind, Digest: proof.Digest})
	}
	sort.Strings(dependencyDigests)
	sortRestoreDependencies(requiredDependencies)
	pointDigest, err := localPointDigest(record)
	if err != nil {
		return blocked("restore-source")
	}
	binding := generated.RestoreSourceBinding{
		Schema: generated.SchemaIDRestoreSourceBinding, SchemaVersion: "1.1.0", PointID: record.Point.PointID,
		PointDigest: pointDigest, ManifestDigest: record.Point.ManifestDigest, VerificationDigest: record.Verification.ProofDigest,
		SourceClass: "local", RepositoryGenerationID: record.Point.RepositoryID, KeyReferenceID: record.KeyReferenceID, DeclaredRPOSeconds: selection.DeclaredRPOSeconds,
		CreatedAt: record.CreatedAt.UTC().Format(time.RFC3339), VerifiedAt: record.VerifiedAt.UTC().Format(time.RFC3339),
		RecoveryEpoch: record.Point.RecoveryEpoch, DependencyDigests: dependencyDigests, RequiredDependencies: requiredDependencies,
		TargetReleaseBuildID: selection.TargetReleaseBuildID, TargetToolVersion: selection.TargetToolVersion, TargetSchemaVersion: selection.TargetSchemaVersion,
	}
	raw, err := json.Marshal(binding)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDRestoreSourceBinding, raw, generated.ContractExact) != nil {
		return blocked("restore-source-binding")
	}
	return VerifiedSource{Binding: binding, Snapshot: reader, DatabaseDigest: record.Point.ContentDigest, Audit: auditPosition}, nil
}

func (verifier SourceVerifier) verifyOffsite(ctx context.Context, selection SourceSelection) (VerifiedSource, error) {
	blocked := func(target string) (VerifiedSource, error) {
		return VerifiedSource{}, failure.New(generated.ErrorCodePrerequisiteBlocked, target, false)
	}
	if selection.RepositoryClass != "critical" || verifier.Offsite == nil || verifier.OffsiteSnapshots == nil || verifier.OffsiteCompatibility == nil || verifier.OffsiteAudit == nil {
		return blocked("restore-offsite-source")
	}
	record, err := verifier.Offsite.CurrentOffsiteRecoverySource(ctx, selection.PointID)
	if err != nil {
		return VerifiedSource{}, err
	}
	now := verifier.Clock().UTC()
	if now.IsZero() || record.PointID != selection.PointID || record.GenerationID == "" || record.RepositoryID == "" || record.SnapshotID == "" || !validWitnessToken(record.KeyReferenceID) ||
		record.Status != "offsite-verified" || record.ProofClass != "qualified-provider" || record.StateRevision != record.CurrentStateRevision ||
		record.RecoveryEpoch != record.CurrentRecoveryEpoch || record.CreatedAt.After(now) || record.VerifiedAt.Before(record.CreatedAt) || record.VerifiedAt.After(now) ||
		!now.Before(record.FullReadValidUntil) || !now.Before(record.FunctionalValidUntil) || now.Sub(record.CreatedAt) > time.Duration(selection.DeclaredRPOSeconds)*time.Second ||
		strconv.FormatInt(record.DatabaseSchemaVersion, 10) != selection.TargetSchemaVersion {
		return blocked("restore-offsite-source")
	}
	for _, value := range []string{record.ManifestDigest, record.InventoryDigest, record.ContentDigest, record.VerificationDigest, record.CatalogDigest, record.DependencyDigest} {
		if !restoreDigest.MatchString(value) {
			return blocked("restore-offsite-source")
		}
	}
	dependencies := append([]string(nil), record.DependencyDigests...)
	for _, value := range dependencies {
		if !restoreDigest.MatchString(value) {
			return blocked("restore-offsite-source-dependencies")
		}
	}
	sort.Strings(dependencies)
	requiredDependencies := append([]generated.RestoreDependencyBinding(nil), record.RequiredDependencies...)
	if len(requiredDependencies) == 0 {
		return blocked("restore-offsite-source-dependencies")
	}
	sortRestoreDependencies(requiredDependencies)
	if err := verifier.OffsiteCompatibility.VerifyOffsiteRestoreCompatibility(ctx, selection, record); err != nil {
		return VerifiedSource{}, err
	}
	reader, err := verifier.OffsiteSnapshots.ResolveOffsite(ctx, record)
	if err != nil || reader == nil {
		return blocked("restore-offsite-source-snapshot")
	}
	auditPosition, err := verifier.OffsiteAudit.VerifyOffsiteRestoreAuditPosition(ctx, record, reader)
	if err != nil || auditPosition.LocalLastEventID < 0 || auditPosition.IndependentLastEventID < auditPosition.LocalLastEventID || !restoreDigest.MatchString(auditPosition.IndependentCheckpointDigest) {
		return blocked("restore-offsite-source-audit")
	}
	pointDigest, err := offsitePointDigest(record, dependencies)
	if err != nil {
		return blocked("restore-offsite-source")
	}
	binding := generated.RestoreSourceBinding{Schema: generated.SchemaIDRestoreSourceBinding, SchemaVersion: "1.1.0", PointID: record.PointID,
		PointDigest: pointDigest, ManifestDigest: record.ManifestDigest, VerificationDigest: record.VerificationDigest,
		SourceClass: "off-site", RepositoryGenerationID: record.GenerationID, KeyReferenceID: record.KeyReferenceID, DeclaredRPOSeconds: selection.DeclaredRPOSeconds,
		CreatedAt: record.CreatedAt.UTC().Format(time.RFC3339), VerifiedAt: record.VerifiedAt.UTC().Format(time.RFC3339),
		RecoveryEpoch: record.RecoveryEpoch, DependencyDigests: dependencies, RequiredDependencies: requiredDependencies,
		TargetReleaseBuildID: selection.TargetReleaseBuildID, TargetToolVersion: selection.TargetToolVersion, TargetSchemaVersion: selection.TargetSchemaVersion}
	raw, err := json.Marshal(binding)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDRestoreSourceBinding, raw, generated.ContractExact) != nil {
		return blocked("restore-offsite-source-binding")
	}
	return VerifiedSource{Binding: binding, Snapshot: reader, DatabaseDigest: record.ContentDigest, Audit: auditPosition}, nil
}

func sortRestoreDependencies(dependencies []generated.RestoreDependencyBinding) {
	sort.Slice(dependencies, func(i, j int) bool {
		if dependencies[i].Kind != dependencies[j].Kind {
			return dependencies[i].Kind < dependencies[j].Kind
		}
		if dependencies[i].DependencyID != dependencies[j].DependencyID {
			return dependencies[i].DependencyID < dependencies[j].DependencyID
		}
		return dependencies[i].Digest < dependencies[j].Digest
	})
}

func offsitePointDigest(record OffsiteRecoverySource, dependencies []string) (string, error) {
	value := struct {
		Domain, PointID, GenerationID, RepositoryID, SnapshotID, ManifestDigest, InventoryDigest, ContentDigest, VerificationDigest, CatalogDigest, DependencyDigest, KeyReferenceID string
		SourceRevision, StateRevision, RecoveryEpoch, DatabaseSchemaVersion                                                                                                          int64
		DependencyDigests                                                                                                                                                            []string
	}{"vegastack-labs.dev/restore-offsite-point/v1", record.PointID, record.GenerationID, record.RepositoryID, record.SnapshotID, record.ManifestDigest, record.InventoryDigest, record.ContentDigest, record.VerificationDigest, record.CatalogDigest, record.DependencyDigest, record.KeyReferenceID, record.SourceRevision, record.StateRevision, record.RecoveryEpoch, record.DatabaseSchemaVersion, dependencies}
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func localPointDigest(record store.LocalRecoverySource) (string, error) {
	value := struct {
		Domain, PointID, SnapshotID, RepositoryID, ManifestDigest, InventoryDigest, ContentDigest, VerificationDigest, KeyReferenceID string
		SourceRevision, StateRevision, RecoveryEpoch                                                                                  int64
	}{"vegastack-labs.dev/restore-local-point/v1", record.Point.PointID, record.SnapshotID, record.Point.RepositoryID, record.Point.ManifestDigest, record.Point.InventoryDigest, record.Point.ContentDigest, record.Verification.ProofDigest, record.KeyReferenceID, record.Point.SourceRevision, record.Verification.StateRevision, record.Verification.RecoveryEpoch}
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
