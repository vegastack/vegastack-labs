// Package recovery contains dormant restore validation seams. No production
// restore route or authority transition is registered until its independent
// source, fence, and audit prerequisites are implemented and reviewed.
package recovery

import (
	"regexp"
	"time"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

var sourceDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// SourceSelection is an operator's bounded intent, never a source proof.
type SourceSelection struct {
	PointID       string
	SourceClass   string
	DeclaredRPO   time.Duration
	RecoveryEpoch int64
}

// SourceQualification is the exact output a future #117 or #114 verifier must
// supply. This value alone does not establish trust in the verifier or snapshot.
type SourceQualification struct {
	PointID            string
	ContentDigest      string
	ManifestDigest     string
	VerificationDigest string
	SourceClass        string
	RecoveryEpoch      int64
	Status             string
	VerifiedAt         time.Time
}

// ValidateSourceCandidate rejects a pending or mismatched point before any
// snapshot is staged. Its callers must independently obtain and verify point
// and qualification records, recheck actual snapshot bytes and dependencies,
// and compare the live revision at the final mutation boundary.
func ValidateSourceCandidate(selection SourceSelection, point generated.RecoveryPoint, qualification SourceQualification, now time.Time) error {
	blocked := func() error { return failure.New(generated.ErrorCodePrerequisiteBlocked, "restore-source", false) }
	if selection.PointID == "" || selection.SourceClass != "local" || selection.DeclaredRPO <= 0 || selection.RecoveryEpoch < 0 || now.IsZero() ||
		point.PointID != selection.PointID || qualification.PointID != selection.PointID ||
		point.SourceKind != selection.SourceClass || qualification.SourceClass != selection.SourceClass ||
		point.ProofClass != "live" ||
		point.RecoveryEpoch != selection.RecoveryEpoch || qualification.RecoveryEpoch != selection.RecoveryEpoch ||
		point.VerificationStatus != "verified" || qualification.Status != "last-good" || point.VerifiedAt == nil ||
		!sourceDigestPattern.MatchString(point.ContentDigest) || !sourceDigestPattern.MatchString(point.ManifestDigest) ||
		!sourceDigestPattern.MatchString(qualification.VerificationDigest) ||
		point.ContentDigest != qualification.ContentDigest || point.ManifestDigest != qualification.ManifestDigest {
		return blocked()
	}
	created, err := time.Parse(time.RFC3339, point.CreatedAt)
	if err != nil || created.After(now) || now.Sub(created) > selection.DeclaredRPO {
		return blocked()
	}
	pointVerified, err := time.Parse(time.RFC3339, *point.VerifiedAt)
	if err != nil || qualification.VerifiedAt.IsZero() || qualification.VerifiedAt.After(now) ||
		!pointVerified.Equal(qualification.VerifiedAt) || pointVerified.Before(created) {
		return blocked()
	}
	return nil
}
