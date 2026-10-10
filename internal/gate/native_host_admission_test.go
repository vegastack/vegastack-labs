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

// Software fixtures exercise the real owning predicates; these values cannot
// enter the protected collector or serve as native qualification evidence.
func nativeHostFixture(t *testing.T, at time.Time) (store.HostAdmissionSnapshot, generated.NativeQualification, generated.QualificationScope, generated.NativeHostObservation) {
	t.Helper()
	s := qualifiedHostSnapshot(t, at)
	d := hostaction.Digest("host-native-software-fixture")
	g := generated.QualificationGuest{Schema: generated.SchemaIDQualificationGuest, SchemaVersion: "1.0.0", GuestID: "subject", HostID: s.Host.HostID, HostIdentityDigest: s.IdentityDigest, InstanceID: "unique-virtual-serial", MachineID: strings.Repeat("a", 32), SSHHostKeyDigest: d, Role: "subject", SnapshotID: "clean", DiskDigest: d, FirmwareDigest: d, CPUs: 1, MemoryBytes: 1073741824, DiskBytes: 3221225472}
	scope := generated.QualificationScope{Schema: generated.SchemaIDQualificationScope, SchemaVersion: "1.0.0", RunID: "native-test", Purpose: "native-debian", ControllerInstanceID: "controller-a", ControlServiceUID: 1001, ControlServiceGID: 1001, PhysicalHostID: "software-fixture", PhysicalHostBootID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", PhysicalHostIdentityDigest: d, SourceCommit: strings.Repeat("a", 40), ExecutableDigest: d, ImageDigest: d, ProfileID: s.Profile.ProfileID, ProfileLockDigest: s.ProfileLockDigest, ConsoleReferenceDigest: d, OutputRoot: "/owned/software-fixture", MaximumDurationSeconds: 3600, IssuedAt: at.Add(-time.Minute).Format(time.RFC3339), ExpiresAt: at.Add(time.Hour).Format(time.RFC3339), Resources: generated.QualificationResources{Schema: generated.SchemaIDQualificationResources, SchemaVersion: "1.0.0", CPUs: 6, MemoryBytes: 8589934592, StorageBytes: 85899345920}, Guests: []generated.QualificationGuest{g}}
	q := generated.NativeQualification{Schema: generated.SchemaIDNativeQualification, SchemaVersion: "1.0.0", Stage: "baseline", ScopeDigest: hostaction.Digest(scope), ProfileID: s.Profile.ProfileID, ProfileLockDigest: s.ProfileLockDigest, SourceCommit: scope.SourceCommit, SourceDigest: nativeSourceDigest(scope.SourceCommit, d), ExecutableDigest: d, ControllerInstanceID: scope.ControllerInstanceID, ObservedAt: at.Format(time.RFC3339), ExpiresAt: at.Add(time.Hour).Format(time.RFC3339), ObserverDigest: d, Producers: []generated.NativeQualificationProducer{}}
	m := s.Measurements[0]
	o := generated.NativeHostObservation{Schema: generated.SchemaIDNativeHostObservation, SchemaVersion: "1.0.0", Binding: generated.NativeObservationBinding{Schema: generated.SchemaIDNativeObservationBinding, SchemaVersion: "1.0.0", ScopeDigest: q.ScopeDigest, GuestID: g.GuestID, ScenarioID: "baseline-access", ControllerInstanceID: scope.ControllerInstanceID, PlanID: m.Plan.PlanID, PlanDigest: m.Plan.PlanDigest, RunID: m.Receipt.RunID, StepID: m.Receipt.StepID, LeaseID: m.Receipt.LeaseID, Nonce: d, Deadline: at.Add(30 * time.Second).Format(time.RFC3339)}, BootID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", QEMUPID: 1234, QEMUStartTimeTicks: 123, ExecutableDigest: d, DiskDigest: d, FirmwareDigest: d, ObservedAt: q.ObservedAt, ProcessState: "running", ConsoleState: "healthy", ChannelDigest: d}
	return s, q, scope, o
}

func TestNativeHostAdmissionUsesActualControlsAndProtectedObservation(t *testing.T) {
	at := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	for _, gateID := range []string{"platform-safety", "host.hardening-baseline"} {
		s, q, scope, o := nativeHostFixture(t, at)
		p, facts, checks, err := NativeHostAdmissionBundle(s, q, scope, o, hostaction.Digest("actual-discovery-fixture"), gateID, at)
		if err != nil || p.RecoveryAccessDigest == "" || len(facts) != 4 || len(checks) < 2 {
			t.Fatal("owning host proof rejected", err)
		}
		if len(NativeHostPrerequisites(p)) != 3 {
			t.Fatal("missing finite prerequisites")
		}
	}
	for _, name := range []string{"physical", "foreign-host", "wrong-scope", "wrong-lease", "stale-console", "wrong-disk", "new-epoch", "missing-control", "missing-recovery-probe", "failed-measurement"} {
		t.Run(name, func(t *testing.T) {
			s, q, scope, o := nativeHostFixture(t, at)
			switch name {
			case "physical":
				s.Host.IdentityClass = "physical"
			case "foreign-host":
				scope.Guests[0].HostID = "foreign"
				q.ScopeDigest = hostaction.Digest(scope)
				o.Binding.ScopeDigest = q.ScopeDigest
			case "wrong-scope":
				q.ScopeDigest = hostaction.Digest("foreign-scope")
			case "wrong-lease":
				o.Binding.LeaseID = "foreign-lease"
			case "stale-console":
				o.ObservedAt = at.Add(-time.Minute).Format(time.RFC3339)
			case "wrong-disk":
				o.DiskDigest = hostaction.Digest("changed")
			case "new-epoch":
				q.RecoveryEpoch++
			case "missing-control":
				s.Results = s.Results[1:]
			case "missing-recovery-probe":
				for i, m := range s.Results {
					if m.ProducerID == "debian-access-probe" {
						s.Results = append(s.Results[:i], s.Results[i+1:]...)
						break
					}
				}
			case "failed-measurement":
				s.Measurements[0].Measurement.Status = "failed"
			}
			if _, _, _, err := NativeHostAdmissionBundle(s, q, scope, o, hostaction.Digest("actual-discovery-fixture"), "platform-safety", at); err == nil {
				t.Fatal("invalid host prerequisites admitted")
			}
		})
	}
}

func TestNativeHostProvenanceRequiresAppliedFullProfileAndHostJoins(t *testing.T) {
	at := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	s, q, scope, o := nativeHostFixture(t, at)
	joined := store.HostNativeProducerBinding{CurrentControllerInstanceID: q.ControllerInstanceID}
	for i, scenario := range generated.NativeQualificationScenarios("baseline") {
		id := fmt.Sprintf("full-profile-%d", i)
		r := generated.NativeProducerReference{Schema: generated.SchemaIDNativeProducerReference, SchemaVersion: "1.0.0", ScenarioID: scenario, HostID: s.Host.HostID, PlanID: id, PlanDigest: o.Binding.PlanDigest, RunID: id, StepID: "step-a", LeaseID: id}
		x := store.NativeProducerExecution{Reference: r, Plan: generated.Plan{PlanID: id, PlanDigest: r.PlanDigest}, Receipt: generated.ExecutionReceipt{PlanID: id, PlanDigest: r.PlanDigest, RunID: id, StepID: r.StepID, LeaseID: id}}
		q.Producers = append(q.Producers, generated.NativeQualificationProducer{Schema: generated.SchemaIDNativeQualificationProducer, SchemaVersion: "1.0.0", Reference: r, HostIdentityDigest: s.IdentityDigest, ReceiptDigest: hostaction.Digest(x.Receipt)})
		joined.Executions = append(joined.Executions, x)
	}
	p, facts, checks, err := NativeHostAdmissionBundle(s, q, scope, o, hostaction.Digest("actual-discovery-fixture"), "platform-safety", at)
	if err != nil {
		t.Fatal(err)
	}
	q.HostProof = &p
	e := validAppliedFixture(at)
	e.GateID = "platform-safety"
	e.SubjectID = s.Host.HostID
	e.CollectorID = "native-debian-228"
	e.AppliedAt = at.Format(time.RFC3339)
	e.ObservedAt = q.ObservedAt
	e.ExpiresAt = q.ExpiresAt
	b := generated.GateEvidenceBundle{Schema: generated.SchemaIDGateEvidenceBundle, SchemaVersion: "1.1.0", CollectorID: e.CollectorID, ObservedAt: q.ObservedAt, NativeQualification: &q, Facts: facts, Checks: checks, Attachments: []generated.GateEvidenceAttachment{}}
	e.BundleDigest = hostaction.Digest(b)
	e.ArtifactDigest = hostaction.Digest(q)
	joined.Qualification = q
	joined.Producers = q.Producers
	joined.Applied = store.HostAppliedBinding{DeclarationID: e.DeclarationID, DeclarationRevision: e.DeclarationRevision, ArtifactDigest: e.ArtifactDigest, BundleDigest: e.BundleDigest, StateRevision: e.StateRevision, ReleaseBuildID: e.ReleaseBuildID, ToolVersion: e.ToolVersion}
	s.NativeProducerBindings = map[string]store.HostNativeProducerBinding{e.EvidenceID: joined}
	v, _ := NewNativeHostProvenance(q.SourceCommit, q.ExecutableDigest, func() time.Time { return at })
	proof, err := v.VerifyHostEvidence(s, e, b)
	if err != nil || proof.Qualification == nil || len(proof.Prerequisites) != 3 {
		t.Fatal("current owning host evidence refused", err)
	}
	e.SourceKind = "fixture"
	e.ProofClass = "fixture"
	if _, err = v.VerifyHostEvidence(s, e, b); err == nil {
		t.Fatal("public copy granted prerequisites")
	}
	e.SourceKind = "local"
	e.ProofClass = "live"
	delete(s.NativeProducerBindings, e.EvidenceID)
	if _, err = v.VerifyHostEvidence(s, e, b); err == nil {
		t.Fatal("unjoined evidence granted prerequisites")
	}
}

func TestNativeHostRoleCollectionRequiresCurrentRoleControls(t *testing.T) {
	at := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	_, q, scope, o := nativeHostFixture(t, at)
	s := qualifiedRoleSnapshot(t, at)
	q.Stage = "role"
	p, facts, checks, err := NativeHostAdmissionBundle(s, q, scope, o, hostaction.Digest("actual-discovery-fixture"), "host.role-admission", at)
	if err != nil || p.HostBindingDigest != s.BindingDigest || len(facts) != 5 || len(checks) < 2 {
		t.Fatal("current role predicates refused", err)
	}
	for _, change := range []string{"no-binding", "missing-control", "role-to-baseline", "baseline-to-role"} {
		copy := cloneHostSnapshot(t, s)
		request := q
		gateID := "host.role-admission"
		switch change {
		case "no-binding":
			copy.RoleBindingDigest = ""
		case "missing-control":
			for i, c := range copy.Results {
				if c.ProducerID == "linux-role" {
					copy.Results = append(copy.Results[:i], copy.Results[i+1:]...)
					break
				}
			}
		case "role-to-baseline":
			gateID = "host.hardening-baseline"
		case "baseline-to-role":
			request.Stage = "baseline"
		}
		if _, _, _, err := NativeHostAdmissionBundle(copy, request, scope, o, hostaction.Digest("actual-discovery-fixture"), gateID, at); err == nil {
			t.Fatal("role prerequisite substitution accepted", change)
		}
	}
}
