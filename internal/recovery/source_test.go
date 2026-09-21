package recovery

import (
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestValidateSourceCandidateRejectsUnqualifiedAndStalePoints(t *testing.T) {
	now := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	point := generated.RecoveryPoint{PointID: "point-a", SourceKind: "local", ProofClass: "live", ContentDigest: testDigest("a"), ManifestDigest: testDigest("b"), CreatedAt: now.Add(-time.Minute).Format(time.RFC3339), VerificationStatus: "pending", RecoveryEpoch: 4}
	selection := SourceSelection{PointID: point.PointID, SourceClass: "local", DeclaredRPO: time.Hour, RecoveryEpoch: 4}
	proof := SourceQualification{PointID: point.PointID, ContentDigest: point.ContentDigest, ManifestDigest: point.ManifestDigest, RecoveryEpoch: 4, SourceClass: "local", Status: "last-good", VerificationDigest: testDigest("c"), VerifiedAt: now.Add(-time.Second)}
	if err := ValidateSourceCandidate(selection, point, proof, now); err == nil {
		t.Fatal("pending point accepted")
	}
	point.VerificationStatus = "verified"
	verifiedAt := proof.VerifiedAt.Format(time.RFC3339)
	point.VerifiedAt = &verifiedAt
	if err := ValidateSourceCandidate(selection, point, proof, now); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*SourceSelection, *generated.RecoveryPoint, *SourceQualification){
		"stale epoch": func(s *SourceSelection, p *generated.RecoveryPoint, q *SourceQualification) { s.RecoveryEpoch++ },
		"wrong point": func(s *SourceSelection, p *generated.RecoveryPoint, q *SourceQualification) { q.PointID = "other" },
		"wrong digest": func(s *SourceSelection, p *generated.RecoveryPoint, q *SourceQualification) {
			q.ContentDigest = testDigest("d")
		},
		"wrong manifest": func(s *SourceSelection, p *generated.RecoveryPoint, q *SourceQualification) {
			q.ManifestDigest = testDigest("d")
		},
		"unqualified": func(s *SourceSelection, p *generated.RecoveryPoint, q *SourceQualification) { q.Status = "pending" },
		"future proof": func(s *SourceSelection, p *generated.RecoveryPoint, q *SourceQualification) {
			q.VerifiedAt = now.Add(time.Minute)
		},
		"expired RPO": func(s *SourceSelection, p *generated.RecoveryPoint, q *SourceQualification) {
			p.CreatedAt = now.Add(-2 * time.Hour).Format(time.RFC3339)
		},
		"wrong class": func(s *SourceSelection, p *generated.RecoveryPoint, q *SourceQualification) {
			q.SourceClass = "off-site"
		},
		"fixture proof": func(s *SourceSelection, p *generated.RecoveryPoint, q *SourceQualification) {
			p.ProofClass = "fixture"
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, p, q := selection, point, proof
			mutate(&s, &p, &q)
			if ValidateSourceCandidate(s, p, q, now) == nil {
				t.Fatal("unsafe source accepted")
			}
		})
	}
}

func testDigest(letter string) string {
	var hex string
	for i := 0; i < 64; i++ {
		hex += letter
	}
	return "sha256:" + hex
}
