package gate

import (
	"context"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// These are explicitly internal software fixtures, never native observations.
func nativeProfileFixture(t *testing.T) (store.HostAdmissionSnapshot, ResolvedScope, time.Time) {
	t.Helper()
	at := time.Date(2026, 10, 10, 4, 45, 0, 0, time.UTC)
	s, e, b := nativeProvenanceFixture(t, at)
	e.ProfileID = e.SubjectID
	e.ArtifactDigest = hostaction.Digest(*b.NativeQualification)
	s.Profile.ProfileID = e.SubjectID
	s.Evidence = []generated.GateEvidence{e}
	s.Bundles = map[string]generated.GateEvidenceBundle{e.EvidenceID: b}
	joined := s.NativeProducerBindings[e.EvidenceID]
	joined.Applied.ArtifactDigest = e.ArtifactDigest
	s.NativeProducerBindings[e.EvidenceID] = joined
	s.AppliedBindings = map[string]store.HostAppliedBinding{e.EvidenceID: joined.Applied}
	q := b.NativeQualification
	s.Qualifications = []store.HostNativeQualification{{Stage: q.Stage, ProfileDigest: q.ProfileLockDigest, EvidenceID: e.EvidenceID, SourceDigest: q.SourceDigest, ObservedAt: q.ObservedAt, ExpiresAt: q.ExpiresAt, RecoveryEpoch: q.RecoveryEpoch}}
	return s, ResolvedScope{ProfileID: e.ProfileID, ProfileVersion: e.ProfileVersion, PolicyID: e.PolicyID, PolicyVersion: e.PolicyVersion, StateRevision: 1}, at
}

func TestNativeProfileGateUsesVerifiedQualification(t *testing.T) {
	s, scope, at := nativeProfileFixture(t)
	// Missing workload prerequisites must not erase separate profile qualification.
	s.Blockers = []string{"host-control-missing"}
	got, err := EvaluateNativeProfileQualification(context.Background(), s, scope, "native.role", at)
	if err != nil || got.Outcome != "passed" || len(got.EvidenceIDs) != 1 || got.EvidenceIDs[0] != s.Qualifications[0].EvidenceID {
		t.Fatalf("current internal profile qualification unavailable: %+v %v", got, err)
	}
}

func TestNativeProfileGateDenials(t *testing.T) {
	for name, change := range map[string]func(*store.HostAdmissionSnapshot, *ResolvedScope, *time.Time){
		"missing-verified-qualification": func(s *store.HostAdmissionSnapshot, _ *ResolvedScope, _ *time.Time) { s.Qualifications = nil },
		"missing-internal-lineage":       func(s *store.HostAdmissionSnapshot, _ *ResolvedScope, _ *time.Time) { s.NativeProducerBindings = nil },
		"different-profile":              func(_ *store.HostAdmissionSnapshot, p *ResolvedScope, _ *time.Time) { p.ProfileID = "other-profile" },
		"different-policy":               func(_ *store.HostAdmissionSnapshot, p *ResolvedScope, _ *time.Time) { p.PolicyVersion = "99.0.0" },
		"old-epoch":                      func(s *store.HostAdmissionSnapshot, _ *ResolvedScope, _ *time.Time) { s.Revision.RecoveryEpoch++ },
		"future-profile-revision": func(s *store.HostAdmissionSnapshot, p *ResolvedScope, _ *time.Time) {
			p.StateRevision = s.Revision.StateRevision + 1
		},
		"expired": func(_ *store.HostAdmissionSnapshot, _ *ResolvedScope, at *time.Time) { *at = at.Add(48 * time.Hour) },
		"fixture-upload": func(s *store.HostAdmissionSnapshot, _ *ResolvedScope, _ *time.Time) {
			s.Evidence[0].SourceKind = "fixture"
			s.Evidence[0].ProofClass = "fixture"
		},
		"wrong-artifact": func(s *store.HostAdmissionSnapshot, _ *ResolvedScope, _ *time.Time) {
			s.Evidence[0].ArtifactDigest = hostaction.Digest("other")
		},
		"newer-invalid-no-old-revival": func(s *store.HostAdmissionSnapshot, _ *ResolvedScope, _ *time.Time) {
			e := s.Evidence[0]
			e.EvidenceID = "newer-invalid"
			e.StateRevision++
			s.Evidence = append(s.Evidence, e)
		},
		"revoked": func(s *store.HostAdmissionSnapshot, _ *ResolvedScope, _ *time.Time) { s.Evidence[0].Status = "revoked" },
		"unverified-source": func(s *store.HostAdmissionSnapshot, _ *ResolvedScope, _ *time.Time) {
			s.Qualifications[0].SourceDigest = hostaction.Digest("different-source")
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, scope, at := nativeProfileFixture(t)
			change(&s, &scope, &at)
			got, err := EvaluateNativeProfileQualification(context.Background(), s, scope, "native.role", at)
			if err == nil && got.Outcome == "passed" {
				t.Fatalf("denied state passed: %+v", got)
			}
		})
	}
}
