package backup

import (
	"context"
	"testing"
	"time"
)

type expectedPointFixture struct{ observation OffsiteGenerationObservation }

func (value expectedPointFixture) ObserveExpectedPoint(context.Context, PendingOffsiteGeneration) (OffsiteGenerationObservation, error) {
	return value.observation, nil
}

type cutoffFixture struct{ put, multipart bool }

func (value cutoffFixture) DenyNewPUT(context.Context, string) (bool, error) { return value.put, nil }
func (value cutoffFixture) DenyMultipartCompletion(context.Context, string) (bool, error) {
	return value.multipart, nil
}

func expectedObservation(pending PendingOffsiteGeneration, now time.Time) OffsiteGenerationObservation {
	return OffsiteGenerationObservation{GenerationID: pending.GenerationID, RepositoryID: pending.RepositoryID, SourcePointID: pending.SourcePointID,
		SourceSnapshotID: pending.SourceSnapshotID, SourceManifestDigest: pending.SourceManifestDigest, SourceInventoryDigest: pending.SourceInventoryDigest,
		SourceContentDigest: pending.SourceContentDigest, SourceDependencyDigest: pending.SourceDependencyDigest, SourceResticDigest: pending.SourceResticDigest,
		KeyReferenceID: pending.KeyReferenceID, SnapshotIDs: []string{pending.OffsiteSnapshotID}, InventoryDigest: pending.OffsiteInventoryDigest,
		RuleDigest: pending.RuleDigest, ObjectCount: pending.ObjectCount, ObjectBytes: pending.ObjectBytes, MetadataValid: true, FullReadSucceeded: true,
		FullReadAt: now.Add(-time.Minute), ObservedAt: now}
}

func testPendingOffsite(now time.Time) PendingOffsiteGeneration {
	return PendingOffsiteGeneration{SourcePointID: "point-a", SourceSnapshotID: offsiteHex("1"), SourceManifestDigest: offsiteDigest("2"), SourceInventoryDigest: offsiteDigest("3"),
		SourceContentDigest: offsiteDigest("4"), SourceDependencyDigest: offsiteDigest("5"), SourceResticDigest: offsiteDigest("6"), KeyReferenceID: "key-a",
		GenerationID: "generation-a", RepositoryID: offsiteHex("7"), OffsiteSnapshotID: offsiteHex("8"), OffsiteInventoryDigest: offsiteDigest("9"), RuleDigest: offsiteDigest("a"),
		SessionExpiries: []time.Time{now.Add(-time.Minute)}, SourceRevision: 4, RecoveryEpoch: 2, ObjectCount: 9, ObjectBytes: 4096, IssuanceStoppedAt: now.Add(-2 * time.Minute)}
}

func offsiteHex(value string) string { return string(makeRepeated(value[0], 64)) }
func makeRepeated(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return result
}

func TestOffsiteVerifierRejectsMissingListedSnapshotDespiteGreenCheck(t *testing.T) {
	now := time.Date(2026, 9, 23, 5, 0, 0, 0, time.UTC)
	pending := testPendingOffsite(now)
	observation := expectedObservation(pending, now)
	observation.SnapshotIDs = nil
	config := OffsiteVerifierConfig{Source: expectedPointFixture{observation}, ProofID: "proof-a", ProofClass: OffsiteProofFixture, Clock: func() time.Time { return now }, FullReadMaximumAge: time.Hour}
	if _, err := VerifyOffsitePoint(context.Background(), config, pending, WriterSealProof{}); err == nil {
		t.Fatal("missing expected snapshot verified")
	}
	observation.SnapshotIDs = []string{pending.OffsiteSnapshotID}
	config.Source = expectedPointFixture{observation}
	proof, err := VerifyOffsitePoint(context.Background(), config, pending, WriterSealProof{})
	if err != nil || proof.Status != OffsiteStatusFixtureOnly {
		t.Fatalf("fixture proof = %#v, %v", proof, err)
	}
}

func TestOffsiteVerifierRejectsMismatchedManifestDependenciesAndFullRead(t *testing.T) {
	now := time.Date(2026, 9, 23, 5, 0, 0, 0, time.UTC)
	pending := testPendingOffsite(now)
	for name, mutate := range map[string]func(*OffsiteGenerationObservation){
		"manifest":     func(value *OffsiteGenerationObservation) { value.SourceManifestDigest = offsiteDigest("f") },
		"dependency":   func(value *OffsiteGenerationObservation) { value.SourceDependencyDigest = offsiteDigest("f") },
		"key":          func(value *OffsiteGenerationObservation) { value.KeyReferenceID = "wrong-key" },
		"corrupt-pack": func(value *OffsiteGenerationObservation) { value.FullReadSucceeded = false },
	} {
		t.Run(name, func(t *testing.T) {
			observation := expectedObservation(pending, now)
			mutate(&observation)
			config := OffsiteVerifierConfig{Source: expectedPointFixture{observation}, ProofID: "proof-a", ProofClass: OffsiteProofFixture, Clock: func() time.Time { return now }, FullReadMaximumAge: time.Hour}
			if _, err := VerifyOffsitePoint(context.Background(), config, pending, WriterSealProof{}); err == nil {
				t.Fatal("mismatched observation verified")
			}
		})
	}
}

func TestSealWriterRequiresExpiryAndBothQualifiedDenials(t *testing.T) {
	now := time.Date(2026, 9, 23, 5, 0, 0, 0, time.UTC)
	pending := testPendingOffsite(now)
	pending.SessionExpiries = []time.Time{now.Add(time.Minute)}
	if _, err := SealWriter(context.Background(), pending, OffsiteProofQualified, now, cutoffFixture{true, true}); err == nil {
		t.Fatal("live session sealed")
	}
	pending.SessionExpiries = []time.Time{{}}
	if _, err := SealWriter(context.Background(), pending, OffsiteProofQualified, now, cutoffFixture{true, true}); err == nil {
		t.Fatal("zero session expiry sealed")
	}
	pending.SessionExpiries = []time.Time{now.Add(-time.Minute)}
	pending.IssuanceStoppedAt = now.Add(time.Minute)
	if _, err := SealWriter(context.Background(), pending, OffsiteProofQualified, now, cutoffFixture{true, true}); err == nil {
		t.Fatal("future issuance cutoff sealed")
	}
	pending.IssuanceStoppedAt = now.Add(-2 * time.Minute)
	if _, err := SealWriter(context.Background(), pending, OffsiteProofQualified, now, cutoffFixture{true, false}); err == nil {
		t.Fatal("multipart completion without denial sealed")
	}
	seal, err := SealWriter(context.Background(), pending, OffsiteProofQualified, now, cutoffFixture{true, true})
	if err != nil || !seal.NewPUTDenied || !seal.MultipartCompletionDenied {
		t.Fatalf("seal = %#v, %v", seal, err)
	}
}

func TestOffsiteVerifierRejectsObservationBeforeIssuanceCutoff(t *testing.T) {
	now := time.Date(2026, 9, 23, 5, 0, 0, 0, time.UTC)
	pending := testPendingOffsite(now)
	observation := expectedObservation(pending, now)
	observation.FullReadAt = pending.IssuanceStoppedAt.Add(-time.Second)
	config := OffsiteVerifierConfig{Source: expectedPointFixture{observation}, ProofID: "proof-before-cutoff", ProofClass: OffsiteProofFixture, Clock: func() time.Time { return now }, FullReadMaximumAge: time.Hour}
	if _, err := VerifyOffsitePoint(context.Background(), config, pending, WriterSealProof{}); err == nil {
		t.Fatal("pre-cutoff full read verified")
	}
}

func TestOffsiteLastGoodRejectsPendingFixtureAndStaleProof(t *testing.T) {
	now := time.Date(2026, 9, 23, 5, 0, 0, 0, time.UTC)
	pending := testPendingOffsite(now)
	observation := expectedObservation(pending, now)
	fixture, err := VerifyOffsitePoint(context.Background(), OffsiteVerifierConfig{Source: expectedPointFixture{observation}, ProofID: "proof-fixture", ProofClass: OffsiteProofFixture, Clock: func() time.Time { return now }, FullReadMaximumAge: time.Hour}, pending, WriterSealProof{})
	if err != nil {
		t.Fatal(err)
	}
	if CanAdvanceOffsiteLastGood(pending, fixture, pending.SourceRevision, pending.RecoveryEpoch) == nil {
		t.Fatal("fixture advanced offsite last-good")
	}
	seal, err := SealWriter(context.Background(), pending, OffsiteProofQualified, now, cutoffFixture{true, true})
	if err != nil {
		t.Fatal(err)
	}
	live, err := VerifyOffsitePoint(context.Background(), OffsiteVerifierConfig{Source: expectedPointFixture{observation}, ProofID: "proof-live", ProofClass: OffsiteProofQualified, Clock: func() time.Time { return now }, FullReadMaximumAge: time.Hour}, pending, seal)
	if err != nil {
		t.Fatal(err)
	}
	if CanAdvanceOffsiteLastGood(pending, live, pending.SourceRevision+1, pending.RecoveryEpoch) == nil {
		t.Fatal("stale proof advanced offsite last-good")
	}
	if err := CanAdvanceOffsiteLastGood(pending, live, pending.SourceRevision, pending.RecoveryEpoch); err != nil {
		t.Fatal(err)
	}
}
