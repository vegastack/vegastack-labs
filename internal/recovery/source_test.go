package recovery

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/store"
)

type sourceReaderStub struct {
	value store.LocalRecoverySource
	err   error
}

func (stub sourceReaderStub) CurrentLocalRecoverySource(context.Context, string) (store.LocalRecoverySource, error) {
	return stub.value, stub.err
}

type snapshotStub struct{}

func (snapshotStub) Restore(context.Context, CandidateTarget) (SnapshotReceipt, error) {
	return SnapshotReceipt{}, nil
}

type snapshotResolverStub struct{ reader SnapshotReader }

func (stub snapshotResolverStub) ResolveLocal(context.Context, store.LocalRecoverySource) (SnapshotReader, error) {
	return stub.reader, nil
}

type compatibilityStub struct{ err error }

func (stub compatibilityStub) VerifyRestoreCompatibility(context.Context, SourceSelection, store.LocalRecoverySource) error {
	return stub.err
}

type auditPositionStub struct {
	value AuditContinuity
	err   error
}

func (stub auditPositionStub) VerifyRestoreAuditPosition(context.Context, store.LocalRecoverySource, SnapshotReader) (AuditContinuity, error) {
	return stub.value, stub.err
}

func TestSourceVerifierRejectsUnqualifiedAndStaleLocalPoints(t *testing.T) {
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	record := validLocalRecoverySource(now)
	selection := SourceSelection{PointID: "point-a", SourceClass: "local", RepositoryClass: "standard", DeclaredRPOSeconds: 3600, TargetReleaseBuildID: "build-a", TargetToolVersion: "1.0.0", TargetSchemaVersion: "21"}
	makeVerifier := func(value store.LocalRecoverySource) SourceVerifier {
		return SourceVerifier{Local: sourceReaderStub{value: value}, Snapshots: snapshotResolverStub{reader: snapshotStub{}}, Compatibility: compatibilityStub{}, Audit: auditPositionStub{value: AuditContinuity{LocalLastEventID: 4, IndependentLastEventID: 4, IndependentCheckpointDigest: "sha256:" + strings.Repeat("9", 64)}}, Clock: func() time.Time { return now }}
	}
	verified, err := makeVerifier(record).Verify(context.Background(), selection)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Binding.PointID != selection.PointID || verified.Binding.SourceClass != "local" || verified.Binding.VerificationDigest != record.Verification.ProofDigest || verified.DatabaseDigest != record.Point.ContentDigest || verified.Snapshot == nil {
		t.Fatalf("verified=%#v", verified)
	}
	for name, mutate := range map[string]func(*store.LocalRecoverySource, *SourceSelection){
		"not last-good":        func(value *store.LocalRecoverySource, _ *SourceSelection) { value.Verification.Status = "fixture-only" },
		"fixture proof":        func(value *store.LocalRecoverySource, _ *SourceSelection) { value.Verification.ProofClass = "fixture" },
		"wrong point":          func(value *store.LocalRecoverySource, _ *SourceSelection) { value.Verification.PointID = "point-b" },
		"stale RPO":            func(value *store.LocalRecoverySource, _ *SourceSelection) { value.CreatedAt = now.Add(-2 * time.Hour) },
		"wrong schema":         func(value *store.LocalRecoverySource, _ *SourceSelection) { value.DatabaseSchemaVersion++ },
		"stale epoch":          func(value *store.LocalRecoverySource, _ *SourceSelection) { value.Verification.RecoveryEpoch++ },
		"off-site unavailable": func(_ *store.LocalRecoverySource, choice *SourceSelection) { choice.SourceClass = "off-site" },
	} {
		t.Run(name, func(t *testing.T) {
			value, choice := record, selection
			mutate(&value, &choice)
			if _, err := makeVerifier(value).Verify(context.Background(), choice); err == nil {
				t.Fatal("unsafe source accepted")
			}
		})
	}
}

func validLocalRecoverySource(now time.Time) store.LocalRecoverySource {
	digest := func(letter string) string { return "sha256:" + strings.Repeat(letter, 64) }
	return store.LocalRecoverySource{
		Verification: store.LocalVerificationReceipt{VerificationID: "verification-a", ProofDigest: digest("a"), PointID: "point-a", RepositoryClass: "standard", Status: "local-verified", ProofClass: "live", ManifestDigest: digest("b"), InventoryDigest: digest("c"), StateRevision: 8, RecoveryEpoch: 3, DependencyTrust: []store.BackupDependencyTrustEvidence{{DependencyID: "binary-a", Kind: "binary", Digest: digest("d")}}},
		Point:        store.PendingRecoveryPoint{PointID: "point-a", RepositoryID: "repository-a", RepositoryClass: "standard", ManifestDigest: digest("b"), ContentDigest: digest("e"), InventoryDigest: digest("c"), SourceRevision: 8, RecoveryEpoch: 3},
		SnapshotID:   "snapshot-a", DatabaseSchemaVersion: 21, CatalogDigest: digest("f"), DependencyDigest: digest("1"), KeyReferenceID: "key-a",
		CreatedAt: now.Add(-time.Minute), VerifiedAt: now.Add(-30 * time.Second), FullReadAt: now.Add(-45 * time.Second), FunctionalRestoredAt: now.Add(-30 * time.Second),
	}
}

func TestSourceBindingRejectsInvalidDependencyDigest(t *testing.T) {
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	record := validLocalRecoverySource(now)
	record.Verification.DependencyTrust[0].Digest = "not-a-digest"
	verifier := SourceVerifier{Local: sourceReaderStub{value: record}, Snapshots: snapshotResolverStub{reader: snapshotStub{}}, Compatibility: compatibilityStub{}, Audit: auditPositionStub{value: AuditContinuity{IndependentCheckpointDigest: "sha256:" + strings.Repeat("9", 64)}}, Clock: func() time.Time { return now }}
	_, err := verifier.Verify(context.Background(), SourceSelection{PointID: "point-a", SourceClass: "local", RepositoryClass: "standard", DeclaredRPOSeconds: 60, TargetReleaseBuildID: "build-a", TargetToolVersion: "1.0.0", TargetSchemaVersion: "21"})
	if err == nil {
		t.Fatal("invalid dependency trust admitted")
	}
}
