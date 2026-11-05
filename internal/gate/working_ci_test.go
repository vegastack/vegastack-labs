package gate

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/debianbaseline"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/linuxrole"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func workingCIFixture(t *testing.T, at time.Time) (store.HostAdmissionSnapshot, ResolvedScope) {
	t.Helper()
	s := qualifiedHostSnapshot(t, at)
	s.Evidence = nil
	s.Bundles = map[string]generated.GateEvidenceBundle{}
	s.AppliedBindings = map[string]store.HostAppliedBinding{}
	s.Qualifications = nil
	s.QualificationDigests = nil
	s.PrerequisiteDigests = nil
	s.PrerequisiteEvidenceIDs = nil
	s.Host.Status = "adopted-unadmitted"
	s.Host.IdentityClass = "physical"
	for i := range s.Measurements {
		s.Measurements[i].Control.IdentityClass = "physical"
		s.Results[i] = s.Measurements[i].Control
	}
	s.AppliedProfile = &store.GateAppliedProfile{ProfileID: "vegastack-labs", ProfileVersion: "1.0.0", PolicyID: "labs-working-ci", PolicyVersion: "1.0.0", Capabilities: []string{"ci.working-demonstration", "ci.working-host." + s.Host.HostID}, StateRevision: 90}
	s.AppliedProfileDigest = hostaction.Digest(*s.AppliedProfile)
	p := s.AppliedProfile
	return s, ResolvedScope{ProfileID: p.ProfileID, ProfileVersion: p.ProfileVersion, PolicyID: p.PolicyID, PolicyVersion: p.PolicyVersion, Capabilities: p.Capabilities, StateRevision: p.StateRevision, RecoveryEpoch: p.RecoveryEpoch}
}

func TestWorkingCIBaselineUsesRealControlsWithoutQualifyingHost(t *testing.T) {
	at := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	s, scope := workingCIFixture(t, at)
	got, err := EvaluateWorkingCI(context.Background(), s, scope, "baseline", at)
	if err != nil || got.Outcome != "passed" || len(got.ControlDigests) != 10 || got.SnapshotDigest != store.HostAdmissionSnapshotDigest(s) || len(got.Deferred) == 0 {
		t.Fatalf("working baseline: %+v, %v", got, err)
	}
	if !WorkingCISelected(s) {
		t.Fatal("applied policy not selected")
	}
	for _, id := range []string{"host.hardening-baseline", "host.role-admission"} {
		full, err := EvaluateHostAdmission(context.Background(), s, scope, id, at)
		if err == nil && full.Outcome == "passed" {
			t.Fatalf("demo fabricated full qualification: %s", id)
		}
	}
}

func TestWorkingCIDeniesInvalidPolicyAndEvidence(t *testing.T) {
	at := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name   string
		change func(*store.HostAdmissionSnapshot, *ResolvedScope)
	}{
		{"unverified-volume-declaration", func(s *store.HostAdmissionSnapshot, _ *ResolvedScope) {
			s.HasVolumeDeclarations = true
			s.RoleBlockers = []string{"host-storage-declaration-unverified"}
		}},
		{"invalid-status", func(s *store.HostAdmissionSnapshot, _ *ResolvedScope) { s.Host.Status = "registered" }},
		{"absent-policy", func(s *store.HostAdmissionSnapshot, _ *ResolvedScope) { s.AppliedProfile = nil }},
		{"wrong-policy", func(s *store.HostAdmissionSnapshot, _ *ResolvedScope) {
			s.AppliedProfile.PolicyID = "other"
			s.AppliedProfileDigest = hostaction.Digest(*s.AppliedProfile)
		}},
		{"wrong-version", func(s *store.HostAdmissionSnapshot, _ *ResolvedScope) {
			s.AppliedProfile.PolicyVersion = "2.0.0"
			s.AppliedProfileDigest = hostaction.Digest(*s.AppliedProfile)
		}},
		{"missing-host-scope", func(s *store.HostAdmissionSnapshot, sc *ResolvedScope) {
			s.AppliedProfile.Capabilities = []string{"ci.working-demonstration"}
			s.AppliedProfileDigest = hostaction.Digest(*s.AppliedProfile)
			sc.Capabilities = s.AppliedProfile.Capabilities
		}},
		{"tampered-profile-digest", func(s *store.HostAdmissionSnapshot, _ *ResolvedScope) {
			s.AppliedProfileDigest = hostaction.Digest("forged")
		}},
		{"wrong-scope", func(_ *store.HostAdmissionSnapshot, sc *ResolvedScope) { sc.PolicyID = "other" }},
		{"epoch", func(s *store.HostAdmissionSnapshot, _ *ResolvedScope) { s.Revision.RecoveryEpoch++ }},
		{"future-profile", func(s *store.HostAdmissionSnapshot, sc *ResolvedScope) {
			s.AppliedProfile.StateRevision = s.Revision.StateRevision + 1
			s.AppliedProfileDigest = hostaction.Digest(*s.AppliedProfile)
			sc.StateRevision = s.AppliedProfile.StateRevision
		}},
		{"wrong-role", func(s *store.HostAdmissionSnapshot, _ *ResolvedScope) { s.Profile.RoleID = "application" }},
		{"declared-volume", func(s *store.HostAdmissionSnapshot, _ *ResolvedScope) { s.VolumeIDs = []string{"data"} }},
		{"missing-control", func(s *store.HostAdmissionSnapshot, _ *ResolvedScope) { s.Results = s.Results[1:] }},
		{"failed-control", func(s *store.HostAdmissionSnapshot, _ *ResolvedScope) {
			s.Results[0].Status = "failed"
			s.Measurements[0].Control = s.Results[0]
		}},
		{"forged-control", func(s *store.HostAdmissionSnapshot, _ *ResolvedScope) {
			s.Measurements[0].Measurement.ConfigurationDigest = hostaction.Digest("forged")
		}},
		{"missing-confirmation", func(s *store.HostAdmissionSnapshot, _ *ResolvedScope) {
			for i, c := range s.Results {
				if c.ControlID == "debian-access-confirm" {
					s.Results = append(s.Results[:i], s.Results[i+1:]...)
					break
				}
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, sc := workingCIFixture(t, at)
			tc.change(&s, &sc)
			got, err := EvaluateWorkingCI(context.Background(), s, sc, "baseline", at)
			if err == nil && got.Outcome == "passed" {
				t.Fatalf("invalid fixture admitted: %+v", got)
			}
		})
	}
	s, sc := workingCIFixture(t, at)
	got, err := EvaluateWorkingCI(context.Background(), s, sc, "baseline", at.Add(25*time.Hour))
	if err == nil && got.Outcome == "passed" {
		t.Fatal("stale controls admitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := EvaluateWorkingCI(ctx, s, sc, "baseline", at); err == nil {
		t.Fatal("cancelled evaluation accepted")
	}
}

// Adapt the existing joined control-role receipt fixture into a CI role with
// actual valid CI role inputs, rather than synthesizing a qualification verdict.
func workingCIRoleFixture(t *testing.T, at time.Time) (store.HostAdmissionSnapshot, ResolvedScope) {
	t.Helper()
	s := qualifiedRoleSnapshot(t, at)
	base, scope := workingCIFixture(t, at)
	s.AppliedProfile = base.AppliedProfile
	s.AppliedProfileDigest = base.AppliedProfileDigest
	s.Evidence = nil
	s.Bundles = map[string]generated.GateEvidenceBundle{}
	s.AppliedBindings = map[string]store.HostAppliedBinding{}
	s.Qualifications = nil
	s.QualificationDigests = nil
	s.PrerequisiteDigests = nil
	s.PrerequisiteEvidenceIDs = nil
	s.VolumeIDs = nil
	s.Storage = store.HostStoragePrerequisites{}
	s.Profile.RoleID = "ci"
	s.Host.Status = "adopted-unadmitted"
	s.Host.IdentityClass = "physical"
	s.NetworkingRequired = true
	rows := s.Measurements
	s.Measurements = nil
	s.Results = nil
	for _, row := range rows {
		if strings.HasPrefix(row.Control.ControlID, "linux.volume-") || row.Control.ControlID == "linux.aide-integrity" {
			continue
		}
		raw, _ := json.Marshal(row)
		var x store.HostAdmissionMeasurement
		json.Unmarshal(raw, &x)
		x.Control.IdentityClass = "physical"
		if x.Control.ProducerID == "debian-baseline" {
			var in generated.DebianBaselineInput
			json.Unmarshal([]byte(x.Plan.HostAction.ActionInput), &in)
			in.RoleID = "ci"
			in.RenderedPolicyDigest = debianbaseline.PolicyDigest(in)
			raw, _ := json.Marshal(in)
			x.Plan.HostAction.ActionInput = string(raw)
			x.Plan.HostAction.ActionInputDigest = hostaction.BytesDigest(raw)
			var err error
			x.Plan.HostBaselineScope, err = debianbaseline.ScopeForRequest(*x.Plan.HostAction)
			if err != nil {
				t.Fatal(err)
			}
			x.Measurement.ConfigurationDigest = x.Plan.HostAction.ActionInputDigest
			x.Control.RoleID = "ci"
		}
		if x.Control.ProducerID == "linux-role" {
			var in generated.LinuxRoleInput
			json.Unmarshal([]byte(x.Plan.HostAction.ActionInput), &in)
			in.RoleID = "ci"
			in.Accounts[0].Selector = "ci"
			in.Accounts[0].UID = in.AutomationUID + 1
			in.Accounts[0].GID = in.AutomationUID + 1
			in.ControlPlainCredentials = nil
			in.ControlEncryptedCredentials = nil
			in.ControlLocalBackup = false
			for i := range in.Directories {
				in.Directories[i].UID = in.Accounts[0].UID
				in.Directories[i].GID = in.Accounts[0].GID
			}
			work := in.Directories[0]
			work.Selector = "work"
			in.Directories = append(in.Directories, work)
			if x.Control.ControlID == "linux.control-service" {
				x.Control.ControlID = "linux.role-workload-isolation"
				x.Measurement.ControlID = x.Control.ControlID
			}
			in.ControlIDs = []string{x.Control.ControlID}
			in.RenderedPolicyDigest = linuxrole.PolicyDigest(in)
			in.RoleBindingDigest = linuxrole.RoleBindingDigest(in)
			if err := linuxrole.ValidateInput(in); err != nil {
				t.Fatalf("CI role input: %s %v", x.Control.ControlID, err)
			}
			// RoleBindingDigest deliberately excludes per-collection control selection.
			if s.RoleBindingDigest == "" || s.RoleBindingDigest == row.Measurement.Role.RoleBindingDigest {
				s.RoleBindingDigest = in.RoleBindingDigest
			}
			if s.RoleBindingDigest != in.RoleBindingDigest {
				t.Fatal("CI role binding differs across measurements")
			}
			raw, _ := json.Marshal(in)
			x.Plan.HostAction.ActionInput = string(raw)
			x.Plan.HostAction.ActionInputDigest = hostaction.BytesDigest(raw)
			var err error
			x.Plan.HostRoleScope, err = linuxrole.ScopeForRequest(*x.Plan.HostAction)
			if err != nil {
				t.Fatal(err)
			}
			x.Measurement.ConfigurationDigest = x.Plan.HostAction.ActionInputDigest
			x.Control.RoleID = "ci"
			x.Measurement.Role.RoleID = "ci"
			x.Measurement.Role.RoleBindingDigest = s.RoleBindingDigest
		}
		if x.Plan.HostAction != nil {
			x.Plan.Operations[0].ArtifactDigest = hostaction.Digest(*x.Plan.HostAction)
			x.Receipt.ArtifactDigest = x.Plan.Operations[0].ArtifactDigest
		}
		resealHostMeasurement(&s, &x)
		s.Measurements = append(s.Measurements, x)
		s.Results = append(s.Results, x.Control)
	}
	return s, scope
}

func TestWorkingCIRoleRequiresBoundMeasuredCI(t *testing.T) {
	at := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	s, scope := workingCIRoleFixture(t, at)
	got, err := EvaluateWorkingCI(context.Background(), s, scope, "role", at)
	if err != nil || got.Outcome != "passed" {
		t.Fatalf("measured CI role: %+v %v", got, err)
	}
	if _, ok := got.ControlDigests["role:linux.role-workload-isolation"]; !ok {
		t.Fatal("workload isolation omitted")
	}
	for _, tc := range []struct {
		name   string
		change func(*store.HostAdmissionSnapshot)
	}{
		{"role-binding", func(s *store.HostAdmissionSnapshot) { s.RoleBindingDigest = hostaction.Digest("other-role") }},
		{"missing-isolation", func(s *store.HostAdmissionSnapshot) {
			for i, c := range s.Results {
				if c.ControlID == "linux.role-workload-isolation" {
					s.Results = append(s.Results[:i], s.Results[i+1:]...)
					break
				}
			}
		}},
		{"declared-volume", func(s *store.HostAdmissionSnapshot) { s.VolumeIDs = []string{"data"} }},
		{"application-role", func(s *store.HostAdmissionSnapshot) { s.Profile.RoleID = "application" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, scope := workingCIRoleFixture(t, at)
			tc.change(&s)
			got, err := EvaluateWorkingCI(context.Background(), s, scope, "role", at)
			if err == nil && got.Outcome == "passed" {
				t.Fatalf("invalid CI role admitted: %+v", got)
			}
		})
	}
	full, err := EvaluateHostAdmission(context.Background(), s, scope, "host.role-admission", at)
	if err == nil && full.Outcome == "passed" {
		t.Fatal("demo upgraded to full role qualification")
	}
}
