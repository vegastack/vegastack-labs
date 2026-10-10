package gate

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// This constructs an internal resolver fixture, never public/native evidence.
func nativeProvenanceFixture(t *testing.T, now time.Time) (store.HostAdmissionSnapshot, generated.GateEvidence, generated.GateEvidenceBundle) {
	t.Helper()
	d := hostaction.Digest("test-only")
	e := validAppliedFixture(now)
	e.GateID, e.SubjectID, e.CollectorID = "native.role", "test-profile", "native-debian-228"
	q := generated.NativeQualification{Schema: generated.SchemaIDNativeQualification, SchemaVersion: "1.0.0", Stage: "role", ScopeDigest: d, ProfileID: e.SubjectID, ProfileLockDigest: d, SourceCommit: strings.Repeat("a", 40), ExecutableDigest: d, ControllerInstanceID: "controller-a", ObservedAt: e.ObservedAt, ExpiresAt: e.ExpiresAt, ObserverDigest: d, Producers: []generated.NativeQualificationProducer{}}
	q.Prerequisites = []generated.NativeQualificationPrerequisite{{Schema: generated.SchemaIDNativeQualificationPrerequisite, SchemaVersion: "1.0.0", Stage: "baseline", EvidenceID: "baseline-evidence", BundleDigest: d, ArtifactDigest: d}}
	q.SourceDigest = nativeSourceDigest(q.SourceCommit, d)
	joined := store.HostNativeProducerBinding{CurrentControllerInstanceID: q.ControllerInstanceID}
	for i, scenario := range generated.NativeQualificationScenarios(q.Stage) {
		id := fmt.Sprintf("producer-%d", i)
		r := generated.NativeProducerReference{Schema: generated.SchemaIDNativeProducerReference, SchemaVersion: "1.0.0", ScenarioID: scenario, HostID: "fixture-host", PlanID: id, PlanDigest: d, RunID: id, StepID: "step-a", LeaseID: id}
		x := store.NativeProducerExecution{Reference: r, Plan: generated.Plan{PlanID: id, PlanDigest: d}, Receipt: generated.ExecutionReceipt{PlanID: id, PlanDigest: d, RunID: id, StepID: r.StepID, LeaseID: id}}
		q.Producers = append(q.Producers, generated.NativeQualificationProducer{Schema: generated.SchemaIDNativeQualificationProducer, SchemaVersion: "1.0.0", Reference: r, HostIdentityDigest: d, ReceiptDigest: hostaction.Digest(x.Receipt)})
		joined.Executions = append(joined.Executions, x)
	}
	b := generated.GateEvidenceBundle{Schema: generated.SchemaIDGateEvidenceBundle, SchemaVersion: "1.1.0", CollectorID: e.CollectorID, ObservedAt: e.ObservedAt, NativeQualification: &q, Attachments: []generated.GateEvidenceAttachment{}, Facts: []generated.GateEvidenceFact{{Schema: generated.SchemaIDGateEvidenceFact, SchemaVersion: "1.1.0", FactID: "native.profile-lock", ValueDigest: d}, {Schema: generated.SchemaIDGateEvidenceFact, SchemaVersion: "1.1.0", FactID: "native.source", ValueDigest: q.SourceDigest}}, Checks: []generated.GateEvidenceCheck{{Schema: generated.SchemaIDGateEvidenceCheck, SchemaVersion: "1.1.0", CheckID: "native.role", VerifierVersion: "1.0.0", Result: "passed", ResultDigest: q.SourceDigest}}}
	e.BundleDigest = hostaction.Digest(b)
	joined.Qualification, joined.Producers = q, q.Producers
	joined.Applied = store.HostAppliedBinding{ReleaseBuildID: e.ReleaseBuildID, ToolVersion: e.ToolVersion, DeclarationID: e.DeclarationID, ArtifactDigest: e.ArtifactDigest, BundleDigest: e.BundleDigest, DeclarationRevision: e.DeclarationRevision, StateRevision: e.StateRevision}
	s := store.HostAdmissionSnapshot{ProfileLockDigest: d, ProfileLock: generated.DebianProfileLock{ExecutableVersion: e.ToolVersion}, Revision: store.RevisionToken{StateRevision: 10}, NativeProducerBindings: map[string]store.HostNativeProducerBinding{e.EvidenceID: joined}}
	return s, e, b
}

func TestNativeProvenanceRequiresCurrentInternalLineage(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	v, err := NewNativeHostProvenance(strings.Repeat("a", 40), hostaction.Digest("test-only"), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	s, e, b := nativeProvenanceFixture(t, now)
	proof, err := v.VerifyHostEvidence(s, e, b)
	if err != nil || proof.Qualification == nil {
		t.Fatal("internal lineage refused", err)
	}
	for _, name := range []string{"public-copy", "no-internal-join", "changed-build", "changed-profile", "restored-controller", "new-epoch", "expired", "revoked", "receipt-substitution", "missing-scenario"} {
		t.Run(name, func(t *testing.T) {
			s, e, b := nativeProvenanceFixture(t, now)
			j := s.NativeProducerBindings[e.EvidenceID]
			switch name {
			case "public-copy":
				e.SourceKind, e.ProofClass = "fixture", "fixture"
			case "no-internal-join":
				delete(s.NativeProducerBindings, e.EvidenceID)
			case "changed-build":
				b.NativeQualification.ExecutableDigest = hostaction.Digest("another-build")
			case "changed-profile":
				s.ProfileLockDigest = hostaction.Digest("another-profile")
			case "restored-controller":
				j.CurrentControllerInstanceID = "controller-b"
			case "new-epoch":
				s.Revision.RecoveryEpoch++
			case "expired":
				e.ExpiresAt = now.Add(-time.Second).Format(time.RFC3339)
			case "revoked":
				e.Status = "revoked"
			case "receipt-substitution":
				j.Executions[0].Receipt.RunID = "unrelated-run"
			case "missing-scenario":
				j.Executions = j.Executions[1:]
			}
			if name != "no-internal-join" {
				s.NativeProducerBindings[e.EvidenceID] = j
			}
			if got, err := v.VerifyHostEvidence(s, e, b); err == nil || got.Qualification != nil {
				t.Fatal("invalid qualification admitted")
			}
		})
	}
}

func TestNativeProvenanceCompleteProducerCapacity(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	v, err := NewNativeHostProvenance(strings.Repeat("a", 40), hostaction.Digest("test-only"), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	for _, count := range []int{52, 64, 65} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			s, e, b := nativeProvenanceFixture(t, now)
			q := b.NativeQualification
			j := s.NativeProducerBindings[e.EvidenceID]
			for len(q.Producers) < count {
				x := j.Executions[0]
				id := fmt.Sprintf("additional-producer-%d", len(q.Producers))
				x.Reference.PlanID, x.Reference.RunID, x.Reference.LeaseID = id, id, id
				x.Plan.PlanID = id
				x.Receipt.PlanID, x.Receipt.RunID, x.Receipt.LeaseID = id, id, id
				p := q.Producers[0]
				p.Reference, p.ReceiptDigest = x.Reference, hostaction.Digest(x.Receipt)
				q.Producers = append(q.Producers, p)
				j.Executions = append(j.Executions, x)
			}
			j.Qualification, j.Producers = *q, q.Producers
			e.BundleDigest = hostaction.Digest(b)
			j.Applied.BundleDigest = e.BundleDigest
			s.NativeProducerBindings[e.EvidenceID] = j
			proof, err := v.VerifyHostEvidence(s, e, b)
			if count <= 64 {
				if err != nil || proof.Qualification == nil {
					t.Fatalf("complete finite producer set refused: %v", err)
				}
				j.Executions[count-1].Receipt.RunID = "substituted-receipt"
				s.NativeProducerBindings[e.EvidenceID] = j
				if proof, err := v.VerifyHostEvidence(s, e, b); err == nil || proof.Qualification != nil {
					t.Fatal("larger producer set bypassed exact receipt binding")
				}
			} else if err == nil || proof.Qualification != nil {
				t.Fatal("unbounded producer set accepted")
			}
		})
	}
}
