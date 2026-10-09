//go:build linux

package api

import (
	"github.com/vegastack/vegastack-labs/internal/gate"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/store"
	"testing"
	"time"
)

// Give independent synthetic producer chains distinct durable identities. The
// observations themselves are constructed against each host's own typed input;
// this only namespaces declarations/evidence and advances their state revisions.
func namespaceReplacementSnapshot(s *store.HostAdmissionSnapshot, namespace string, offset int64) {
	suffix := "-" + namespace
	s.RoleIntentRevision += offset
	s.Revision.StateRevision += offset
	s.DeclarationID += suffix
	s.Results = nil
	s.ActionReceiptDigests = nil
	for i := range s.Measurements {
		x := &s.Measurements[i]
		x.Plan.PlanID += suffix
		x.Plan.DeclarationID += suffix
		x.Plan.Binding.StateRevision += offset
		x.Control.DeclarationID = x.Plan.DeclarationID
		x.Receipt.PlanID = x.Plan.PlanID
		x.Receipt.ReceiptID += suffix
		x.Receipt.RunID += suffix
		x.Receipt.StepID += suffix
		x.Receipt.LeaseID += suffix
		resealHostMeasurement(s, x)
		s.Results = append(s.Results, x.Control)
	}
	bundles := map[string]generated.GateEvidenceBundle{}
	bindings := map[string]store.HostAppliedBinding{}
	for i := range s.Evidence {
		e := &s.Evidence[i]
		prior := e.EvidenceID
		b := s.Bundles[prior]
		binding := s.AppliedBindings[prior]
		e.EvidenceID += suffix
		e.DeclarationID += suffix
		e.StateRevision += offset
		binding.DeclarationID = e.DeclarationID
		binding.StateRevision = e.StateRevision
		bundles[e.EvidenceID] = b
		bindings[e.EvidenceID] = binding
	}
	s.Bundles = bundles
	s.AppliedBindings = bindings
	for i := range s.Qualifications {
		s.Qualifications[i].EvidenceID += suffix
	}
	for key, id := range s.PrerequisiteEvidenceIDs {
		s.PrerequisiteEvidenceIDs[key] = id + suffix
	}
	s.BindingDigest = hostaction.Digest(struct{ Host, Namespace string }{s.Host.HostID, namespace})
}

func TestReplacementTwoIndependentRoleAdmissions(t *testing.T) {
	at := time.Now().UTC().Truncate(time.Second)
	f := replacementPersistedRoleFixture(t, &at, true)
	input := admissionAccessInput(t, "aide", "cryptsetup-bin")
	input.HostID = "second-host"
	input.HostIdentityDigest = hostaction.Digest("second-host-identity")
	input.RollbackSpecification.HostID = input.HostID
	input.RollbackSpecification.HostIdentityDigest = input.HostIdentityDigest
	input.RollbackDigest = hostaction.Digest(input.RollbackSpecification)
	expected := replacementQualifiedRoleSnapshotForInput(t, at, input, "application")
	namespaceReplacementSnapshot(&expected, input.HostID, 100)
	f.seed.exec(`UPDATE system_meta SET state_revision=200 WHERE id=1`)
	replacementPersistRoleSnapshot(t, &at, expected, "second-role-declaration", 101, &f)
	profile, err := f.repo.GetAppliedProfileScope(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	scope := gate.ResolvedScope{ProfileID: profile.ProfileID, ProfileVersion: profile.ProfileVersion, PolicyID: profile.PolicyID, PolicyVersion: profile.PolicyVersion, Capabilities: profile.Capabilities, StateRevision: profile.StateRevision, RecoveryEpoch: profile.RecoveryEpoch}
	for _, host := range []string{f.input.HostID, input.HostID} {
		snapshot, err := f.repo.ResolveHostAdmission(f.ctx, host)
		if err != nil {
			t.Fatal(host, err)
		}
		result, err := gate.EvaluateHostAdmission(f.ctx, snapshot, scope, "host.role-admission", at)
		if err != nil || result.Outcome != "passed" {
			t.Fatalf("%s admission %s/%s: %v", host, result.Outcome, result.ReasonCode, err)
		}
	}
}
