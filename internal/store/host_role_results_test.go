package store

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"testing"
)

func TestRoleMeasurementRequiresExactRoleProducerAndProjection(t *testing.T) {
	d := hostaction.Digest("role")
	p := generated.Plan{HostAction: &generated.HostActionRequest{ActionID: "debian.role.collect", ActionInputDigest: d}, HostRoleScope: &generated.HostRoleScope{RoleID: "application", RoleBindingDigest: d, ControlIDs: []string{"linux.role-identity-paths"}}}
	m := generated.AccessMeasurement{ControlID: "linux.role-identity-paths", ProducerID: "linux-role", ProducerVersion: "1.0.0", Kind: "role", ConfigurationDigest: d, Status: "passed", Role: &generated.RoleObservation{RoleID: "application", RoleBindingDigest: d, FactsDigest: d, Verification: "effective-probe"}}
	if err := validateRoleMeasurement(p, m, 0); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func(*generated.AccessMeasurement)
	}{
		{"wrong-role", func(m *generated.AccessMeasurement) { m.Role.RoleID = "control" }},
		{"wrong-binding", func(m *generated.AccessMeasurement) { m.Role.RoleBindingDigest = hostaction.Digest("old") }},
		{"baseline-source", func(m *generated.AccessMeasurement) { m.ProducerID = "debian-baseline" }},
		{"missing-observation", func(m *generated.AccessMeasurement) { m.Role = nil }},
		{"unavailable-pass", func(m *generated.AccessMeasurement) { m.Role.Verification = "unavailable" }},
		{"baseline-projection", func(m *generated.AccessMeasurement) { m.Baseline = &generated.BaselineObservation{} }},
		{"source-probe", func(m *generated.AccessMeasurement) { m.Probe = &generated.AccessProbeObservation{} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			copy := m
			role := *m.Role
			copy.Role = &role
			test.change(&copy)
			if validateRoleMeasurement(p, copy, 0) == nil {
				t.Fatal("invalid role observation accepted")
			}
		})
	}
}
func TestRoleIntentInvalidatesAffectedBaselineAndPriorRole(t *testing.T) {
	p := generated.Plan{PlanID: "new", Binding: generated.PlanBinding{StateRevision: 11}, HostAction: &generated.HostActionRequest{HostID: "host-a", ActionID: "debian.role.apply"}, HostRoleScope: &generated.HostRoleScope{AffectedBaselineControlIDs: []string{"linux.resource-health"}}}
	for _, test := range []struct {
		id, producer string
		want         bool
	}{{"linux.resource-health", "debian-baseline", true}, {"linux.role-identity-paths", "linux-role", true}, {"linux.time-sync", "debian-baseline", false}} {
		old := HostAdmissionMeasurement{Plan: generated.Plan{PlanID: "old", Binding: generated.PlanBinding{StateRevision: 10}}, Control: generated.HostControlResult{ControlID: test.id, ProducerID: test.producer}}
		if got := hostMutationInvalidates(p, old, "host-a"); got != test.want {
			t.Fatalf("%s invalidation=%v", test.id, got)
		}
		p.HostAction.ActionID = "debian.role.collect"
		if hostMutationInvalidates(p, old, "host-a") {
			t.Fatal("collection invalidates evidence")
		}
		p.HostAction.ActionID = "debian.role.apply"
	}
}
