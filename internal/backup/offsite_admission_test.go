package backup

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type fakeOffsiteSource struct {
	point VerifiedCriticalPoint
	err   error
}

func (source fakeOffsiteSource) VerifiedCriticalPoint(context.Context, string) (VerifiedCriticalPoint, error) {
	return source.point, source.err
}

func offsiteDigest(c string) string { return "sha256:" + strings.Repeat(c, 64) }
func testOffsitePolicy(now time.Time) OffsitePolicy {
	return OffsitePolicy{PolicyID: "policy-a", ProfileID: "labs-r2", GenerationID: "generation-a", Bucket: "bucket-a", Prefix: "critical",
		ParentReferenceID: "reference-a", ParentFingerprint: offsiteDigest("a"), MaximumBytes: 1024, MaximumPUTs: 100, MaximumLISTs: 20,
		MaximumRetainedGenerations: 10, RuleLimit: 1000, RetentionWindow: 14 * 24 * time.Hour, SessionTTL: 5 * time.Minute, Clock: func() time.Time { return now }}
}
func testVerifiedCriticalPoint(now time.Time) VerifiedCriticalPoint {
	objects := []ExpectedObject{{Type: "config", Name: "config", Bytes: 1, Digest: offsiteDigest("1")}, {Type: "keys", Name: "key-a", Bytes: 2, Digest: offsiteDigest("2")}, {Type: "snapshots", Name: "snapshot-a", Bytes: 3, Digest: offsiteDigest("3")}}
	return VerifiedCriticalPoint{PointID: "point-a", PolicyID: "policy-a", PolicyDigest: offsiteDigest("b"), RepositoryID: "critical-local", RepositoryClass: "critical",
		ManifestDigest: offsiteDigest("c"), SnapshotID: "snapshot-a", InventoryDigest: ExpectedInventoryDigest(objects), ContentDigest: offsiteDigest("d"),
		KeyReferenceID: "key-reference-a", ResticDigest: offsiteDigest("e"), DependencyDigest: ExpectedDependencyInventoryDigest([]ExpectedDependency{}),
		ProofStatus: "local-verified", ProofClass: "live", VerificationID: "verification-a", SourceRevision: 2, StateRevision: 2, RecoveryEpoch: 7,
		ObjectCount: int64(len(objects)), ObjectBytes: 6, ExpectedObjects: objects, ExpectedDependencies: []ExpectedDependency{}, FullReadValidUntil: now.Add(time.Hour), FunctionalValidUntil: now.Add(time.Hour)}
}

func TestAdmitOffsitePointRequiresVerifiedCurrentCriticalSource(t *testing.T) {
	now := time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC)
	for _, status := range []string{"pending", "fixture-only", "full-payload-due", "failed"} {
		t.Run(status, func(t *testing.T) {
			point := testVerifiedCriticalPoint(now)
			point.ProofStatus = status
			if _, err := AdmitOffsitePoint(context.Background(), fakeOffsiteSource{point: point}, testOffsitePolicy(now), "point-a", 7); err == nil {
				t.Fatal("non-verified source admitted")
			}
		})
	}
	point, err := AdmitOffsitePoint(context.Background(), fakeOffsiteSource{point: testVerifiedCriticalPoint(now)}, testOffsitePolicy(now), "point-a", 7)
	if err != nil || point.PointID != "point-a" {
		t.Fatalf("admit = %#v, %v", point, err)
	}
	if _, err := AdmitOffsitePoint(context.Background(), fakeOffsiteSource{err: errors.New("unavailable")}, testOffsitePolicy(now), "point-a", 7); err == nil {
		t.Fatal("source outage admitted")
	}
}
